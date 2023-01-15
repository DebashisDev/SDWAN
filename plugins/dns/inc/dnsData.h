/*
 * DnsData.h
 *
 *  Created on: 11-Jun-2016
 *      Author: deb
 */

#ifndef INC_DNSDATA_H_
#define INC_DNSDATA_H_

#include <string.h>    //strlen
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>

#include "smGlobal.h"
#include "IPGlobal.h"
#include "Log.h"

#include "GConfig.h"
#include "BaseConfig.h"

class dnsData : public BaseConfig
{
	private:
		void	lockDnsMap();
		void	unLockDnsMap();

	public:
		dnsData();
		~dnsData();

		void 		updateUrl(uint32_t resolvedip, std::string url);
		void		getUrl(std::string& url, uint32_t ip);
		string		lookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap);

		void 		updateV6Url(string resolvedip, string url);
		void 		getDNSV6UrlForIP(std::string& url, char *ip);

		string 		getDNSKey(uint32_t destAddrLong, uint32_t sourceAddrLong);
};

#endif /* INC_DNSDATA_H_ */
