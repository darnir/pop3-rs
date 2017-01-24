#[derive(Serialize, Deserialize, Debug)]
pub struct AccountConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub auth: String,
    pub maildir: PathBuf,
}
