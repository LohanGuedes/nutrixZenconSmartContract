// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract AccessControl {
  event GrantRole(bytes32 indexed role, address indexed account);
  event RevokeRole(bytes32 indexed role, address indexed account);

  mapping(bytes32 => mapping(address => bool)) public roles; // Mapping for ROLES
  bytes32 public constant ADMIN = keccak256('ADMIN');        // nutrix adminn
  bytes32 public constant PATIENT = keccak256('PATIENT');    // Nutrix Patient
  bytes32 public constant MED = keccak256('MEDIC');

  modifier onlyRole(bytes32 _role) {
    require(roles[_role][msg.sender], "not authorized");
    _;
  }

  function _grantRole(bytes32 _role, address _account) internal {
    roles[_role][_account] = true;
    emit GrantRole(_role, _account);
  }

  function grantRole(bytes32 _role, address _account) external onlyRole(ADMIN) {
    _grantRole(_role, _account);
  }

  function revokeRole(bytes32 _role, address _account) external onlyRole(ADMIN) {
    roles[_role][_account] = false;
    emit RevokeRole(_role, _account);
  }
}

contract NutrixMedSec is ERC721URIStorage, AccessControl {
  event CreateUser(address _userWallet, string _initialPatientRecord);
  event CreateMed(address _userWallet, string _medId);
  event addUserRecordByWallet(address _userWallet);
  event grantMedAccess(address user, address med, string medId);
  event med_readLatestRecord(address _userWallet, address _medWallet);
  event DebugLatestRecord(address userWallet, string record);

  struct UserData {
    string[] _patientRecords;
    mapping(address => MedData) _meds;
    bool isValue;
  }

  struct MedData {
    string _medId;
    bool isValue;
  }

  mapping(address => UserData) internal usersData;
  mapping(address => MedData) internal medsData;

  constructor() ERC721("NutrixMedSec", "NMS") {
    _grantRole(ADMIN, msg.sender);
  }

  function createPatient(address _userWallet, string memory _initialPatientRecord) public onlyRole(ADMIN) {
    require(!usersData[_userWallet].isValue, "User already exists");
    UserData storage userData = usersData[_userWallet];
    userData.isValue = true;
    userData._patientRecords.push(_initialPatientRecord);
    emit CreateUser(_userWallet, _initialPatientRecord);
  }

  function createMed(address _medWallet, string memory _medId) public onlyRole(ADMIN) {
    require(!medsData[_medWallet].isValue, "User already exists");
    MedData storage medData = medsData[_medWallet];
    medData._medId = _medId;
    medData.isValue = true;
    emit CreateMed(_medWallet, _medId);
  }

  function addNewPatientRecord(address userWallet, string memory newPatientRecord) public onlyRole(ADMIN) {
    require(usersData[userWallet].isValue, "Given Wallet does not have data mapped to it");
    usersData[userWallet]._patientRecords.push(newPatientRecord);
    emit addUserRecordByWallet(userWallet);
  }

  function grantMedAccessToPatient(address user, address med) public onlyRole(ADMIN) {
    require(usersData[user].isValue, "Given Wallet is not a recognized user");
    require(medsData[med].isValue, "Given Wallet is not a recognized user");

    
    usersData[user]._meds[med] = medsData[med];
  }

  modifier medHasAccess(address user, address med) {
    require(usersData[user]._meds[med].isValue, "Given wallet has no access to user data");
    _;
  }

  function getPatientLatestRecord(address user, address med) public onlyRole(ADMIN) medHasAccess(user, med) returns (string memory) {
    uint256 latest = usersData[user]._patientRecords.length - 1;
    string memory latestRecord = usersData[user]._patientRecords[latest];
    emit DebugLatestRecord(user, latestRecord);
    emit med_readLatestRecord(user, med);
    return latestRecord;
  }
}
