use base64::{decode, encode};
use sha2::{Sha256, Digest};
use std::time::SystemTime;

use ureq::*;
use serde_derive::{Deserialize, Serialize};
use ureq::serde_json::Value;

use std::fmt::Write;

const ENDPOINT: &str = "https://userservice.rebellion.co.uk/rosacap";
const APPLICATION: &str = "2000ad";
const APPLICATION_KEY: &str = "ibzGYfeYbyVtbxDlzudDXdpwPk3u9UJ8sRin8WS7DKU=";

pub struct Client {
    device_id: String,
    security_token: Option<String>,
    renewal_token: Option<String>,
    user_id: Option<u64>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Medium {
    pub id: u64,
    pub content_type: String,
    pub file_name: String,
    pub md5: String,
    pub file_size: u64
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Product {
    pub id: u64,
    pub product_code: String,
    pub name: String,
    pub media: Vec<Medium>
}

enum RosacapParserState {
    Ground,
    Head,
    HeadData,
    Parameter,
    ParameterData,
    NoMore
}

impl Client {
    pub fn new(device_id: String) -> Self {
        Client {
            device_id,
            security_token: None,
            renewal_token: None,
            user_id: None
        }
    }

    pub fn login(&mut self, email_address: &str, password: &str) -> Result<(), String> {
        let challenge_token = self.auth_request(email_address)?;

        let mut hasher = Sha256::new();
        hasher.update(email_address);
        hasher.update(b"REBELLION");
        hasher.update(password);
        let id_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(decode(challenge_token.as_str()).unwrap());
        hasher.update(id_hash);
        let token_bytes = hasher.finalize();

        self.authenticate(challenge_token, encode(token_bytes))
    }

    pub fn get_entitlements(&mut self) -> Result<Vec<String>, String> {
        let obj = self.request("prodGetEntitlements", 100, Some(ureq::json!({
            "returnType": "productCodes"
        })))?;

        if let Some(obj) = obj.as_object() {
            if let Some(codes) = obj.get("productCodes") {
                if let Some(codes) = codes.as_array() {
                    Ok(codes.iter().map(|v| v.as_str().unwrap().to_string()).collect())
                } else {
                    Err("Expected productCodes to be an array".to_string())
                }
             } else {
                Err("Could not find product codes".to_string())
            }
        } else {
            Err(format!("Expected and object got: {:?}", obj))
        }
    }

    pub fn request_medium(&mut self, medium_id: u64) -> Result<String, String> {
        let resp = self.request("prodRequestMedium", 100, Some(ureq::json!({
            "application": APPLICATION,
            "mediumId": medium_id
        })))?;

        if let Some(obj) = resp.as_object() {
            if let Some(url) = obj.get("downloadUrl") {
                Ok(url.as_str().unwrap().to_string())
            } else {
                Err("downloadUrl not found".to_string())
            }
        } else {
            Err(format!("Expected an object, got: {:?}", resp))
        }
    }

    pub fn get_products(&mut self, product_codes: &Vec<String>) -> Result<Vec<Product>, String> {
        let mut result = Vec::new();
        for pcodes in product_codes.chunks(5) {
            let mut chunk = self.get_products_batch(&pcodes.to_vec())?;

            result.append(&mut chunk);
        }

        Ok(result)
    }

    // apparently the API can not handle large numbers of product codes so we have to batch the requests
    fn get_products_batch(&mut self, product_codes: &Vec<String>) -> Result<Vec<Product>, String> {
        let mut hasher = Sha256::new();
        hasher.update(ureq::json!({
            "now": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            "codes": product_codes
        }).to_string());
        let req_hash = hasher.finalize();

        let resp = self.request("prodGetProducts", 200, Some(ureq::json!({
            "application": APPLICATION,
            "productIds": Value::Null,
            "productCodes": product_codes,
            "withBasicData": true,
            "id": encode(req_hash)
        })))?;

        if let Some(arr) = resp.as_array() {
            let result = arr.iter().fold(Vec::new(), |mut products, value| {
                if let Some(obj) = value.as_object() {
                    if let Some(t) = obj.get("type") {
                        if let Some(s) = t.as_str() {
                            if s.eq_ignore_ascii_case("product") {
                                if let Some(data) = obj.get("data") {
                                    products.insert(0, Product{
                                        id: obj.get("id").unwrap().as_u64().unwrap(),
                                        product_code: data.get("productCode").unwrap().as_str().unwrap().to_string(),
                                        name: data.get("name").unwrap().as_str().unwrap().to_string(),
                                        media: vec![]
                                    });
                                }
                            } else if s.eq_ignore_ascii_case("medium") {
                                if let Some(data) = obj.get("data") {
                                    if let Some(prod) = products.first_mut() {
                                        prod.media.push(Medium {
                                            id: obj.get("id").unwrap().as_u64().unwrap(),
                                            content_type: data.get("contentType").unwrap().as_str().unwrap().to_string(),
                                            file_name: data.get("filename").unwrap().as_str().unwrap().to_string(),
                                            md5: data.get("md5").unwrap().as_str().unwrap().to_string(),
                                            file_size: data.get("size").unwrap().as_u64().unwrap()
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                products
            });


            Ok(result)
        } else {
            Err(format!("Expected an array got: {:?}", resp))
        }
    }

    fn request(&mut self, request: &str, version: u32, parameters: Option<Value>) -> Result<Value, String> {
        let mut req_body = String::new();
        if let Some(parameters) = parameters {
            let head = if let Some(token) = &self.security_token {
                ureq::json!({"request": request, "version": version, "objects": 1, "securityToken": token}).to_string()
            } else {
                ureq::json!({"request": request, "version": version, "objects": 1}).to_string()
            };

            let params = parameters.to_string();

            write!(&mut req_body, "ROSACAP/200\nHEAD[{}@]\n{}\nPARAMETERS[{}@]\n{}\n", head.len(), head, params.len(), params).unwrap();
        } else {
            let head = if let Some(token) = &self.security_token {
                ureq::json!({"request": request, "version": version, "objects": 0, "securityToken": token}).to_string()
            } else {
                ureq::json!({"request": request, "version": version, "objects": 0}).to_string()
            };

            write!(&mut req_body, "ROSACAP/200\nHEAD[{}@]\n{}\n", head.len(), head).unwrap();
        }

        match ureq::post(ENDPOINT)
            .set("content-type", "application/binary")
            .set("x-requested-with", "com.rebellion.app2000ad")
            .send_string(req_body.as_str()) {
            Ok(resp) => {
                if let Ok(resp) = resp.into_string() {
                    //println!("resp = {:?}", resp);
                    let mut lines = resp.lines();

                    lines.try_fold((RosacapParserState::Ground, Value::Null), |(state, mut value), line| {
                        match state {
                            RosacapParserState::Ground => {
                                if line.starts_with("ROSACAP") {
                                    Ok((RosacapParserState::Head, value))
                                } else {
                                    Err("Invalid format returned".to_string())
                                }
                            },
                            RosacapParserState::Head => {
                                if line.starts_with("HEAD") {
                                    Ok((RosacapParserState::HeadData, value))
                                } else {
                                    Err(format!("Expected HEAD got: {:?}", line))
                                }
                            },
                            RosacapParserState::HeadData => {
                                if let Ok(head) = serde_json::from_str::<Value>(line) {
                                    if let Some(head) = head.as_object() {
                                        if let Some(response_code) = head.get("responseCode") {
                                            if response_code.as_str().unwrap().eq_ignore_ascii_case("SUCCESS") {
                                                // we have a security token, so grab it for later
                                                if let Some(security_token) = head.get("securityToken") {
                                                    self.security_token = security_token.as_str().map(|v| v.to_string());
                                                }

                                                if let Some(objects) = head.get("objects") {
                                                    if let Some(count) = objects.as_i64() {
                                                        if count == 1 {
                                                            Ok((RosacapParserState::Parameter, value))
                                                        } else {
                                                            Ok((RosacapParserState::Parameter, Value::Array(vec![])))
                                                        }
                                                    }  else {
                                                        Err(format!("expected a number got: {:?}", objects))
                                                    }
                                                } else {
                                                    Err(format!("could not locate object count: {:?}", value))
                                                }
                                            } else {
                                                Err(head.get("message").unwrap_or(response_code).to_string())
                                            }
                                        } else {
                                            Err(format!("No response code: {:?}", head))
                                        }
                                    } else {
                                        Err(format!("expected a JSON object got: {:?}", head))
                                    }
                                } else {
                                    Err(format!("Invalid head data: {:?}", line))
                                }
                            },
                            RosacapParserState::Parameter => {
                                if line.starts_with("PARAMETERS") || line.starts_with("OBJECT") {
                                    Ok((RosacapParserState::ParameterData, value))
                                } else {
                                    Err(format!("Expected PARAMETERS got: {:?}", line))
                                }
                            },

                            RosacapParserState::ParameterData => {
                                if let Ok(parameters) = serde_json::from_str::<Value>(line) {
                                    if value.is_array() {
                                        let arr = value.as_array_mut().unwrap();
                                        arr.push(parameters);

                                        Ok((RosacapParserState::Parameter, value))
                                    } else {
                                        Ok((RosacapParserState::NoMore, parameters))
                                    }
                                } else {
                                    Err(format!("expected JSON got: {:?}", line))
                                }
                            },

                            RosacapParserState::NoMore => {
                                Err(format!("Unexpected data found: {:?}", line))
                            }
                        }
                    }).map(|(_, result)| result)
            } else {
                    Err("Could not read body of response".to_string())
                }
            },
            Err(e) => Err(e.to_string())
        }
    }

    fn auth_request(&mut self, email_address: &str) -> Result<String, String> {
        let resp = self.request("authRequest", 100,
                                Some(
                                            ureq::json!({
                                                "application": APPLICATION,
                                                "applicationKey": APPLICATION_KEY,
                                                "build": "na",
                                                "deviceId": self.device_id,
                                                "deviceClass": "na",
                                                "platform": "na",
                                                "platformVersion": "na",
                                                "installationId": "na",
                                                "email": email_address
                                        }))
        )?;

        if let Some(obj) = resp.as_object() {
            if let Some(token) = obj.get("challengeToken") {
                Ok(token.as_str().unwrap_or("").to_string())
            } else {
                Err("Expected challengeToken in response".to_string())
            }
        } else {
            Err("Expected an object in the response".to_string())
        }
    }

    fn authenticate(&mut self, challenge_token: String, verify_token: String) -> Result<(), String> {
        let resp = self.request("authAuthenticate", 100,
                                Some(
                                    ureq::json!({
                                                "application": APPLICATION,
                                                "challengeToken": challenge_token,
                                                "verifyToken": verify_token
                                        }))
        )?;

        if resp.is_array() {
            let resp = resp.as_array().unwrap();

            self.renewal_token = resp.get(0).and_then(|v| v.as_object().and_then(|v| v.get("renewalToken").and_then(|v| Some(v.to_string()))));
            self.user_id = resp.get(1).and_then(|v| v.as_object().and_then(|v| v.get("id").and_then(|v| v.as_u64())));
            Ok(())
        } else {
            Err(format!("Expected an array got: {:?}", resp))
        }
    }
}