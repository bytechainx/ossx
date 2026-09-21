//! 最小示例：构造配置、客户端与预签名 URL（**不发起网络请求**，可直接运行）。
//!
//! ```bash
//! cargo run --example basic
//! ```

use ossx::{OssClient, OssConfig, PresignOptions};

fn main() -> Result<(), ossx::OssError> {
    // 生产环境请从环境变量装载：OssConfig::from_env()（前缀 FOUNDATIONX_OSSX_）
    let config = OssConfig::builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("your-access-key-secret")
        .max_in_flight(8)
        .build()?;

    // 构造客户端只做本地校验；put_object / get_object / ping 才真正打网
    let client = OssClient::new(config)?;
    println!("endpoint = {}", client.config().endpoint);
    println!(
        "retry_max_attempts = {}",
        client.retry_config().max_attempts
    );

    let presigned = client.presign_url("dir/object.txt", &PresignOptions::default())?;
    println!("presigned = {presigned}");

    Ok(())
}
