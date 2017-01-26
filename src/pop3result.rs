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
    pub mbox_stat: Option<POP3Stat>,
    pub mailbox: Vec<EmailMetadata>,
}
