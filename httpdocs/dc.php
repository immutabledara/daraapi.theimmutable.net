<?php
require __DIR__.'/vendor/autoload.php';
header('Content-Type: application/json; charset=utf-8');
if (isset($_REQUEST["domain"])){
	$JSONResponse="PASS";
	$targetDomain=$_REQUEST["domain"];

	$pornCheckNS = array('208.67.222.123','208.67.220.123'); //OpenDNS FamilyCrap
	$pornCheckFail = '146.112.61.106'; //unknown result here is an exception.. we give it 0.0.0.0

	$malwareCheckNS = array('9.9.9.9', '149.112.112.112'); //Quad9 malware Check
	$malwareCheckFail = '0.0.0.0'; //unknown or bad result here is 0.0.0.0, we still give exceptions 0.0.0.0

	$pornCheck = new Net_DNS2_Resolver(array('nameservers' => $pornCheckNS));
		try {
			$pornCheckResult = $pornCheck->query("$targetDomain", 'A')->answer{0}->address;
		} catch(Net_DNS2_Exception $e) {
			$pornCheckResult="0.0.0.0";
		}

	$malwareCheck = new Net_DNS2_Resolver(array('nameservers' => $malwareCheckNS));
		try {
			$malwareCheckResult = $malwareCheck->query("$targetDomain", 'A')->answer{0}->address;
		} catch(Net_DNS2_Exception $e) {
			$malwareCheckResult="0.0.0.0";
		}

	if ((isset($pornCheckResult))&&($pornCheckResult==$pornCheckFail)) {
		$JSONPornCheck="FAIL";
	} else {
		$JSONPornCheck="PASS";
	}

	if ((isset($malwareCheckResult))&&($malwareCheckResult==$malwareCheckFail)) {
		$JSONMalwareCheck="FAIL";
	} else {
		$JSONMalwareCheck="PASS";
	}

} else {
	$targetDomain="";
	$JSONResponse="FAIL";
	$JSONPornCheck="FAIL";
	$JSONMalwareCheck="FAIL";
}

$checkResult = array(
	'd' => "$targetDomain",
	'r' => "$JSONResponse",
	'p' => "$JSONPornCheck",
	'm' => "$JSONMalwareCheck"
);

echo json_encode($checkResult);
?>
