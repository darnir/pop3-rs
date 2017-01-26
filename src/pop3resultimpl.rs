use pop3result::{POP3Stat, POP3List, EmailMetadata, POP3Retr};
use regex::Regex;


lazy_static! {
    static ref STAT_REGEX: Regex = Regex::new(r"(?P<nmsg>\d+) (?P<size>\d+)").unwrap();
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
