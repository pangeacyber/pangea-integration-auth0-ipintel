exports.onExecutePostLogin = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event.configuration.DOMAIN;
    const intelprovider = event.configuration.PROVIDER;
    const config = new Pangea.PangeaConfig({domain: domain});
    const audit = new Pangea.AuditService(token, config);
    const ipIntel = new Pangea.IPIntelService(token, config);

    const ip = event.request.ip;
    const options = {provider: intelprovider, verbose: true, raw: true};

    let context = {
        "connection": event.connection,
        "request": event.request,
        "user": event.user
    };
    let data = {
        "actor": event.user.email,
        "action": "IP Reputation",
        "target": event.request.hostname,
        "new": context,
        "source": ip
    };

    let ip_response;
    try {
        //console.log("Checking IP Reputation: '%s'", ip);
        ip_response = await ipIntel.reputation(ip, options);
        data.new['ip_response'] = ip_response.gotResponse.body;
        //console.log("Response: ", ip_response.gotResponse.body);
    } catch (error) {
        ip_response = {"status": "Failed", "summary": error};
    }


    if (ip_response.status == "Success" && ip_response.result.data.score < 70) {
        data["status"] = "Success";
        data["message"] = "Passed IP Rep Check";
    } else {
        api.access.deny('IP_check_failed', "Login Failed");
        data["status"] = "Failed";
        data["message"] = "Failed IP Rep Check - " + ip_response.summary;
    }

    console.log("Pangea Execution Data: ", data);
    const logResponse = await audit.log(data);
    //console.log("Data: ", logResponse)
};
