use std::collections::HashMap;

#[derive(Debug)]
pub struct EmailMetadata {
    pub msg_id: u32,
    pub msg_size: u32,
}

#[derive(Debug)]
pub struct POP3Stat {
    pub mbox_size: u32,
    pub num_mails: u32,
}

#[derive(Debug)]
pub struct POP3List {
    pub mailbox: Vec<EmailMetadata>,
}

#[derive(Debug)]
pub struct POP3Retr {
    pub msg_data: String,
}

#[derive(Debug)]
pub struct POP3Uidl {
    pub mailbox: HashMap<u32, String>,
    pub reverse_map: HashMap<String, u32>,
}
