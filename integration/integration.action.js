exports.onExecutePostLogin = async (event, api) => {
	  const Pangea = require('node-pangea');
	  const domain = "aws.us.pangea.cloud";
	  const token = event.secrets.TOKEN;
	  const configId = event.configuration.CONFIGID;
	  const config = new Pangea.PangeaConfig({ domain: domain, configId: configId });
	  const audit = new Pangea.AuditService(token, config);
	  const ipintel = new Pangea.IPIntelService(token, config);
	  
	  const ip = event.request.ip;
          const options = { provider: "crowdstrike", verbose: true, raw: true };
	  let context = {
		      "connection":event.connection,
		      "request":event.request,
		      "user":event.user
		      };
	  let data = {
		      "actor": event.user.email,
		      "action": "IP Check",
		      "target": event.request.hostname,
		      "new": context,
		      "source": ip
		      };
	  
	  var ip_response;
	  try{
		      //console.log("Checking Embargo IP : '%s'", ip);
		      ip_response = await ipintel.lookup(ip, options);
		      data.new['ip_response'] = ip_response.gotResponse.body;
		      //console.log("Response: ", ebmargo_response.gotResponse.body);
		    } catch(error){
			        ip_response = {"status":"Failed", "summary":error};
			      };
	  
	  if (ip_response.status == "Success" && ip_response.result.count == 0){
		      data["status"] = "Success";
		      data["message"] = "Passed IP Check";
		    }
	  else{
		      // localize the error message 
		      const LOCALIZED_MESSAGES = {
			            en: 'IP Check Failed.',
			            es: 'No tienes permitido registrarte.'
			          };
		      const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
		      api.access.deny('IP_check_failed', userMessage);
		      data["status"] = "Failed";
		      data["message"] = "Failed IP Check - " + ip_response.summary;
		    };
	  //console.log("Data: ", data);
	  const logResponse = await audit.log(data);
	  //console.log("Data: ", logResponse)
	};
