use pop3result::{POP3Stat, POP3List, EmailMetadata, POP3Retr, POP3Uidl};
use std::collections::HashMap;
use regex::Regex;


lazy_static! {
    static ref STAT_REGEX: Regex = Regex::new(r"(?P<nmsg>\d+) (?P<size>\d+)").unwrap();
    static ref UIDL_REGEX: Regex = Regex::new(r"(?P<msgid>\d+) (?P<uidl>[\x21-\x7E]{1,70})").unwrap();
}

impl POP3Stat {
    pub fn parse(stat_line: &str) -> POP3Stat {
        let stat_cap = STAT_REGEX.captures(stat_line).unwrap();
        POP3Stat {
            num_mails: stat_cap.name("nmsg").unwrap().as_str().parse::<u32>().unwrap(),
            mbox_size: stat_cap.name("size").unwrap().as_str().parse::<u32>().unwrap(),
        }
    }
}

impl POP3List {
    pub fn parse(list_data: &[String]) -> POP3List {
        let mut mbox: Vec<EmailMetadata> = Vec::new();
        let beginitr = if list_data.len() > 1 {1} else {0};

        // Parse all the other lines that contain details
        for line in list_data[beginitr..].iter() {
            let cap = STAT_REGEX.captures(line).unwrap();
            mbox.push(EmailMetadata {
                msg_id: cap.name("nmsg").unwrap().as_str().parse::<u32>().unwrap(),
                msg_size: cap.name("size").unwrap().as_str().parse::<u32>().unwrap(),
            })
        }
        POP3List {
            mailbox: mbox,
        }
    }
}

impl POP3Retr {
    pub fn parse(retr_data: &[String]) -> POP3Retr {
        trace!("Parsing output of RETR");
        let mut data = String::new();
        for line in retr_data[1..].iter() {
            data.push_str(line);
        }
        POP3Retr { msg_data: data }
    }
}

impl POP3Uidl {
    pub fn parse(uidl_data: &[String]) -> POP3Uidl {
        let mut uidl_map = HashMap::new();
        let beginitr = if uidl_data.len() > 1 {1} else {0};

        for line in uidl_data[beginitr..].iter() {
            let cap = UIDL_REGEX.captures(line).unwrap();
            let msgid = cap.name("msgid").unwrap().as_str().parse::<u32>().unwrap();
            let uidl = cap.name("uidl").unwrap().as_str().to_owned();
            uidl_map.insert(msgid, uidl);
        }
        POP3Uidl { mailbox: uidl_map }
    }
}
