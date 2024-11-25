use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::header::AUTHORIZATION;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::str::FromStr;
use reqwest::Method;

const ACCESS_KEY_ID: &str = "your ak";
const SECRET_ACCESS_KEY: &str = "your sk";
const ADDR: &str = "https://mercury.volcengineapi.com";
const HOST: &str = "mercury.volcengineapi.com";
const PATH: &str = "/";
const SERVICE: &str = "volc_torchlight_api";
const REGION: &str = "cn-north-1";
const ACTION: &str = "ChatCompletion";
const VERSION: &str = "2024-01-01";


async fn do_request(method: &str, queries: BTreeMap<String, String>, body: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // 1. 构建请求
    let mut queries = queries;
    queries.insert("Action".to_string(), ACTION.to_string());
    queries.insert("Version".to_string(), VERSION.to_string());
    let mut query_string = String::new();
    for (key, value) in &queries {
        query_string.push_str(&format!("{}={}&", key, value));
    }
    query_string.pop();
    let request_addr = format!("{}{}?{}", ADDR, PATH, query_string);
    println!("request addr: {}", request_addr);

    // 2. 构建签名材料
    let now: DateTime<Utc> = Utc::now();
    let date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let auth_date = &date[0..8];

    let payload = hex::encode(Sha256::digest(&body));

    let signed_headers = vec![
        "host",
        "x-date",
        "x-content-sha256",
        "content-type",
    ];

    let mut header_list = Vec::new();
    for header in &signed_headers {
        if *header == "host" {
            header_list.push(format!("{}:{}", header, HOST));
        } else if *header == "x-date" {
            header_list.push(format!("{}:{}", header, date));
        } else if *header == "x-content-sha256" {
            header_list.push(format!("{}:{}", header, payload));
        } else if *header == "content-type" {
            header_list.push(format!("{}:{}", header, "application/json"));
        }
    }
    let header_string = header_list.join("\n");

    let canonical_string = format!(
        "{}\n{}\n{}\n{}\n\n{}\n{}",
        method,
        PATH,
        query_string.replace('+', "%20"),
        header_string,
        signed_headers.join(";"),
        payload
    );
    println!("canonical string:\n{}", canonical_string);

    let hashed_canonical_string = hex::encode(Sha256::digest(canonical_string.as_bytes()));
    println!("hashed canonical string: {}", hashed_canonical_string);

    let credential_scope = format!("{}/{}/{}/request", auth_date, REGION, SERVICE);
    let sign_string = format!(
        "HMAC-SHA256\n{}\n{}\n{}",
        date,
        credential_scope,
        hashed_canonical_string
    );
    println!("sign string:\n{}", sign_string);

    // 3. 构建认证请求头
    let signed_key = get_signed_key(SECRET_ACCESS_KEY, auth_date, REGION, SERVICE).await;
    let signature = hex::encode(hmac_sha256(&signed_key, &sign_string));
    println!("signature: {}", signature);

    let authorization = format!(
        "HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        ACCESS_KEY_ID,
        credential_scope,
        signed_headers.join(";"),
        signature
    );

    let client = reqwest::Client::new();
    let mut request_builder = client.request(
        Method::from_str(method).unwrap(),
        &request_addr,
    );
    for header in &signed_headers {
        if *header == "host" {
            request_builder = request_builder.header("Host", HOST);
        } else if *header == "x-date" {
            request_builder = request_builder.header("X-Date", date.clone());
        } else if *header == "x-content-sha256" {
            request_builder = request_builder.header("X-Content-Sha256", payload.clone());
        } else if *header == "content-type" {
            request_builder = request_builder.header("Content-Type", "application/json");
        }
    }
    request_builder = request_builder.header(AUTHORIZATION, authorization);

    // 处理请求体
    let request = request_builder.body(body);

    // 4. 打印请求，发起请求
    println!("request:\n{:?}", request);
    let response = request.send().await?;
    println!("response status: {}", response.status());

    // 5. 打印响应
    let status  = response.status();
    let content = response.text().await?;
    println!("response bytes: {:?}", content);

    if status.is_success() {
        println!("请求成功");
    } else {
        println!("请求失败");
    }

    Ok(())
}

async fn get_signed_key(
    secret_access_key: &str,
    auth_date: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret_access_key.as_bytes()).unwrap();
    mac.update(auth_date.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&result).unwrap();
    mac.update(region.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&result).unwrap();
    mac.update(service.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&result).unwrap();
    mac.update(b"request");
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[tokio::main]
async fn main() {
    // GET 请求例子
    // let mut query1 = HashMap::new();
    // query1.insert("Limit".to_string(), "1".to_string());
    // query1.insert("Scope".to_string(), "Custom".to_string());
    // do_request("GET", query1, vec![]).await.unwrap();

    // Post 请求例子
    let b_t = Utc::now();
    let json_string = r#"{
		"bot_id": "7439931489394066953",
		"messages": [
		  {
			"role": "user",
			"content": "帮我查一些关于汽车的视频！"
		  }
		]
	  }"#;
    let mut query2 = BTreeMap::new();
    do_request("POST", query2, json_string.as_bytes().to_vec())
     .await
     .unwrap();
    let e_t = Utc::now() - b_t;
    println!("Run time: {:?}", e_t);
}
