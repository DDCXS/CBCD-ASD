// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;

contract DroneAuthentication {
    // 结构体定义
    struct Certificate {
        uint256 issueTime;   // 发行时间
        uint256 expiryTime;  // 过期时间
        bytes32 certHash;    // 证书哈希值
        bool status;         // 证书状态，true 表示有效， false 表示撤销
    }

    struct Drone {
        address droneAddress;    // 无人机地址
        Certificate certificate; // 无人机证书信息
    }

    struct GroundStation {
        address stationAddress;  // 地面站地址
        bytes32 publicKey;       // 地面站公钥
        bytes32 privateKeyHash;  // 地面站私钥哈希
        mapping(address => Drone) drones; // 所在域内无人机地址映射
    }

    mapping(address => GroundStation) public groundStations;

    // 初始化地面站信息
    function initializeGroundStation(address _stationAddress, bytes32 _publicKey, bytes32 _privateKeyHash) public {
        GroundStation storage station = groundStations[_stationAddress];
        station.stationAddress = _stationAddress;
        station.publicKey = _publicKey;
        station.privateKeyHash = _privateKeyHash;
    }

    // 注册无人机并颁发证书
    function registerDrone(address _stationAddress, address _droneAddress, bytes32 _certHash) public {
        GroundStation storage station = groundStations[_stationAddress];
        require(station.stationAddress == msg.sender, "Only the ground station can register a drone");

        Drone storage drone = station.drones[_droneAddress];
        drone.droneAddress = _droneAddress;
        drone.certificate = Certificate({
            issueTime: block.timestamp,
            expiryTime: block.timestamp + 3600, // 默认1小时
            certHash: _certHash,
            status: true
        });
    }

    // 更新无人机的证书信息
    function updateCertificate(address _stationAddress, address _droneAddress, bytes32 _newCertHash, uint256 _newExpiryTime) public {
        GroundStation storage station = groundStations[_stationAddress];
        require(station.stationAddress == msg.sender, "Only the ground station can update a certificate");

        Drone storage drone = station.drones[_droneAddress];
        require(drone.certificate.status == true, "Certificate is revoked");

        drone.certificate.certHash = _newCertHash;
        drone.certificate.expiryTime = _newExpiryTime;
    }

    // 撤销无人机证书
    function revokeCertificate(address _stationAddress, address _droneAddress) public {
        GroundStation storage station = groundStations[_stationAddress];
        require(station.stationAddress == msg.sender, "Only the ground station can revoke a certificate");

        Drone storage drone = station.drones[_droneAddress];
        drone.certificate.status = false;
    }

    // 跨域认证无人机的证书信息
    function crossDomainAuth(address _requestStationAddress, address _droneAddress, bytes32 _certHash, address _droneDomainAddress) public view returns (string memory) {
        GroundStation storage requestStation = groundStations[_requestStationAddress];
        require(requestStation.stationAddress != address(0), "Requesting ground station does not exist");

        GroundStation storage droneDomain = groundStations[_droneDomainAddress];
        require(droneDomain.stationAddress != address(0), "Drone domain ground station does not exist");

        Drone storage drone = droneDomain.drones[_droneAddress];
        require(drone.certificate.status == true, "Certificate is revoked");
        require(drone.certificate.certHash == _certHash, "Invalid certificate hash");
        require(drone.certificate.expiryTime > block.timestamp, "Certificate has expired");

        return "Cross Domain Authentication success";
    }
}
