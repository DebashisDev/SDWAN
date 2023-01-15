/*
 * Initialize.cpp
 *
 *  Created on: 30 Nov 2021
 *      Author: Debashis
 */

#include "Initialize.h"

Initialize::Initialize()
{
	ipSubNet();
}

Initialize::~Initialize()
{ }

void Initialize::ipSubNet()
{
	printf("ipSubNet Initialized....\n");

	initSection::ipSubNetMap.insert(std::pair<int, std::string>(0, "0.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(1, "128.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(2, "192.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(3, "224.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(4, "240.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(5, "248.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(6, "252.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(7, "254.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(8, "255.0.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(9, "255.128.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(10, "255.192.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(11, "255.224.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(12, "255.240.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(13, "255.248.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(14, "255.252.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(15, "255.254.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(16, "255.255.0.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(17, "255.255.128.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(18, "255.255.192.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(19, "255.255.224.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(20, "255.255.240.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(21, "255.255.248.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(22, "255.255.252.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(23, "255.255.254.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(24, "255.255.255.0"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(25, "255.255.255.128"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(26, "255.255.255.192"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(27, "255.255.255.224"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(28, "255.255.255.240"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(29, "255.255.255.248"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(30, "255.255.255.252"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(31, "255.255.255.254"));
	initSection::ipSubNetMap.insert(std::pair<int, std::string>(32, "255.255.255.255"));
}

