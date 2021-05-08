
#[test]
fn test_parse_address() -> Result<(),()>{
    let _: crate::keys::Address = "nV9B2sb2yfRvdzMWfohZoiDbj185J9Dq1y".parse().unwrap();
    Ok(())
}


//bitcoin       1Bf9sZvBHPFGVPX71WX2njhd1NXKv5y7v5
//dogecoin      D5gKqqDSirsdVpNA9efWKaBmsGD7TcckQ9
//doge test     nV9B2sb2yfRvdzMWfohZoiDbj185J9Dq1y
//transaction 不用修改
