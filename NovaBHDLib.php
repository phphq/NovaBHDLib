<?php
declare(strict_types = 1);
/*
//================================================================================
* Novahq.net Novaworld BHD Library *
//================================================================================
:- First Build: July 21st 2021
:- Last Build: July 21st 2021
:- Author: Scott Lucht <scott@novahq.net> http://www.novahq.net
:- Compatibility: NovaLogic's DFBHD
:-
:- This program is distributed in the hope that it will be useful,
:- but WITHOUT ANY WARRANTY; without even the implied warranty of
:- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
:-
:- PUBLIC RELEASE: You may share or make modifications to this file
:-
//================================================================================
* Description
//================================================================================
:- A library for building custom BHD lobbies. Retrieves BHD server list from the
:- official Novaworld GLB file. Simulates Novaworld login to retrieve missing 
:- server info such as port and ck. Pings BHD servers without Novaworld and 
:- converts NovaKeys to and from IPAddress:Port.
//================================================================================
* Usage
//================================================================================
:- See examples below
//================================================================================
* Bug Reports
//================================================================================
:- If you have any issues with this library, please post in the Novahq.net Forums
:- This script was built and tested with PHP 7.3.
//================================================================================
* Credits
//================================================================================
:- This was possible with the help / knowledge of various people such as: 
:- thor, IcIshoot, SkyWalker, deadbolt, tremor, chancellor, Dstructr and more
//================================================================================
* Change log
//================================================================================
:- Version 1.0.0
:-		1) Initial Release
:-
:- Version 1.0.1
:-		1) Few minor fixes
:-
*/

//======================================================================
// USAGE EXAMPLES
//======================================================================
$Nova = new Nova();

echo "<html><head><title>NOVA BHD Library</title></head><body><pre>";
//----------------------------------------------------------------------
// Logs into Novaworld with your credentials to retrieve the GLB file
// and server info using the RID from the server list above.
// This is the only way to get the servers port and ck
//----------------------------------------------------------------------
$nw_login = $Nova->nwLogin('YOUR_NW_USERNAME', 'YOUR_NW_PASSWORD');

//----------------------------------------------------------------------
// Decrypts & Decodes the Novaworld 
// BHD GLB File to get current Novaworld Server List
// http://nw10.novaworld.net/bhd_6.glb?a=1
//----------------------------------------------------------------------
$glb = $Nova->glbOpen('http://nw10.novaworld.net/bhd_6.glb?a=1');

// Decrypt the GLB
$decrypted = $Nova->glbDecrypt($glb);

// Decrypt the GLB
$decoded = $Nova->glbDecode($decrypted);

// debug: print_r($Nova->glbErrors());

// Get the server list
$server_list = $Nova->glbServerList();

//----------------------------------------------------------------------
// Loops through the glb server list, adds the port to the array
//----------------------------------------------------------------------
foreach($server_list AS $rid => $server_details) {

	// Extracts data from the servers join page
	$join_data = $Nova->nwServerExtract($rid);

	// Updates the server list to include the port and other info
	if(!$Nova->glbUpdateServer($rid, $join_data))
		echo "Could not update server with RID: ".$rid."\n";

}

//----------------------------------------------------------------------
// Prints the server list array
//----------------------------------------------------------------------
echo "<h1>Server List Array (Excludes Port)</h1>\n";
print_r($server_list);
echo "\n";
echo "\n";

//----------------------------------------------------------------------
// Prints nice JSON output that includes server port (Use after running login)
//----------------------------------------------------------------------
echo "<h1>JSON Server List</h1>\n";
echo $Nova->printJsonServerList(true);
echo "\n";
echo "\n";

//----------------------------------------------------------------------
// Verbose lobby login debugging
//----------------------------------------------------------------------
echo "<h1>Verbose cURL Debug</h1>\n";
echo "\n";
echo "\n";
print_r($Nova->lobbyVerbose());

//----------------------------------------------------------------------
// Ping a BHD server and get the current status and details
//----------------------------------------------------------------------
$ping = $Nova::nwServerPing('207.178.209.215', 17479);

echo "<h1>NovaPing result from 207.178.209.215:17479</h1>\n";
print_r($ping);
echo "\n";
echo "\n";

//----------------------------------------------------------------------
// Converts IP:Port to encrypted NovaKey
//----------------------------------------------------------------------
echo "<h1>NovaKey from 207.178.209.215:17479</h1>\n";
echo $Nova::string2nk('207.178.209.215:17479');
echo "\n";
echo "\n";

//----------------------------------------------------------------------
// Converts NovaKey to IP:Port
//----------------------------------------------------------------------
echo "<h1>IPAddress:Port from fiocjqmdjglbldlmkjjim</h1>\n";
echo $Nova::nk2string('fiocjqmdjglbldlmkjjim');
echo "\n";
echo "\n";

echo "</pre></body></html>";

//======================================================================
//======================================================================
//======================================================================
// class:NOVA
//======================================================================
//======================================================================
//======================================================================
class Nova {

	private $glb_server_offset = 112;
	private $pattern_data = "DATA";

	protected $glb_errors = array();
	protected $server_list = array();

	// Novaworld lobby info
	private $lobby_cookies = array();
	private $lobby = array(
		"UserAgent" => "NovaLogic IBrowse 2.0",
		"LoginUrl" => "http://nw10.novaworld.net/NWLogin.dll",
		"LoginData" => array(
			"success" => "bhd_6_main.htm",
			"failure" => "bhd_6_login.htm",
			"enterkey" => "bhd_6_term.htm",
			"msgbase" => "bhd_6_msg.htm",
			"relay" => "bhd_6_relay.htm",
			"nodb" => "bhd_6_nodb.htm",
			"pfid" => "26"
		),
		"JoinUrl" => "http://nw10.novaworld.net/NWJoin.dll",
		"JoinString" => "http://nw10.novaworld.net/NWJoin.dll?success=bhd_6_join.joi&failure=bhd_6_lobby.htm&relay=bhd_6_relay.htm&msgbase=bhd_6_msg.htm&nodb=bhd_6_nodb.htm&pfid=26&mode=login&rid=",
	);

	protected $lobby_verbose = array();

	//======================================================================
	/*====================================================================*/
	//======================================================================
	/** 
	 * Pings BHD Server to get it's current status
	 *
	 * @param	string $ip - IP Address
	 * @param	string $port - Port
	 * @param	string $payload - Bytes to send
	 * @return	array - Result
	 *
	 */
	public static function nwServerPing(string $ip, int $port, string $payload = "\xa0\xf1\x88\xce\x10\x10\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00") : array {

		// Validate IP Address
		if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || $port <= 0 || $port > 65535)
			return array('Status' => 'Invalid IPv4 / Port');

		// Open UDP connection
		$socket = @fsockopen("udp://".$ip, $port);

		if(!$socket)
			return array('Status' => 'OFFLINE');

		@socket_set_blocking($socket, false);

		// Send payload packet
		@fwrite($socket, $payload);

		// Sleep ~3.5 for response
		usleep(350000);

		// Receive the data to $recv_bytes
		$recv_bytes = 288;

		$recv_data = @fread($socket, $recv_bytes);
		@fclose($socket);

		// If data was not the expected length return error
		if(strlen($recv_data) != $recv_bytes)
			return array('Status' => 'recv_data != recv_bytes');

		// Map ord() to recv_data
		$recv_data = array_map('ord', str_split($recv_data));

		// Game Type list
		$game_types = array(
			2 => "COOP",
			0 => "DM",
			1 => "TDM",
			4 => "KOTH",
			3 => "TKOTH",
			5 => "CTF",
			6 => "SD",
			7 => "AD",
			8 => "FB",
		);
	
		$server_name_start = 44;
		$server_name_max_len = 25;

		$game_type =  $recv_data[268];
		$dedicated = $recv_data[272] == 1;
		$private = false; //?
		$version = sprintf('%02d', $recv_data[279]);
		$version .= '.'.sprintf('%02d', $recv_data[278]);
		$version .= '.'.sprintf('%02d', $recv_data[277]);
		$version .= '.'.sprintf('%02d', $recv_data[276]);
		$max_players =  $recv_data[36];
		$current_players =  $recv_data[40];

		$server_name = '';
		for($i = $server_name_start; $i < $server_name_start + $server_name_max_len; $i++)
			$server_name .= chr($recv_data[$i]);
		
		// Compile return result
		return array(
			'Status' => "OK",
			'Version' => $version,
			'ServerName' => trim($server_name) ? trim($server_name) : 'Unnamed',
			'GameType' => array_key_exists($game_type, $game_types) ? $game_types[$game_type] : 'Unknown',
			'Dedicated' => $dedicated ? 'Y' : 'N',
			'Private' => $private ? 'Y' : 'N',
			'PlayersMax' => $dedicated ? $max_players-1 : $max_players,
			'PlayersCurrent' => $dedicated ? $current_players-1 : $current_players,
		);

	}

	/** 
	 * IPAddress:Port into Encrypted NovaKey
	 *
	 * @param	string $str - String to encode
	 * @param	bool $pad_right - Pad data right
	 * @param	string $nk - NovaLogics Encryption Key
	 * @return	string - Encrypted NovaKey
	 *
	 */
	public static function string2nk(string $str, bool $pad_right = false, string $nk = 'diheijefhgcdjcgcjcfbd') : string {

		$out_nk = $nk;

		if(stripos($str, ":") !== false && $pad_right) {

			$parts = explode(":", $str);

			$str  = str_pad($parts[0], 15, chr(0x20), STR_PAD_RIGHT);
			$str .= ":";
			$str .= str_pad($parts[1], 5, chr(0x20), STR_PAD_RIGHT);

			$out_nk_len = strlen($str);

		} else if($str == "0") {

			$str = "0000";
			$out_nk_len = 4;

		} else if(strlen($nk) == 4) {

			//ck so only the length of the key
			$out_nk_len = strlen($nk);

		} else {

			//lw fix?
			$out_nk_len = strlen($str);

		}

		for($i = 0; $i < strlen($nk); $i++)
			$out_nk[$i] = @chr(ord($str[$i]) + ord($nk[$i]) - 0x30);

		return substr($out_nk, 0, $out_nk_len);
	}

	/** 
	 * Encrypted NovaKey to IPAddress:Port
	 *
	 * @param	string $str - NovaKey
	 * @param	string $nk - NovaLogics Encryption Key
	 * @return	string - IPAddress:Port
	 *
	 */
	public static function nk2string(string $str, string $nk = 'diheijefhgcdjcgcjcfbd') : string {

		$out_nk = $nk;

		$str_len = strlen($str);

		for($i = 0; $i < strlen($nk); $i++) {

			if($i >= $str_len) 
				break;

			$out_nk[$i] = chr(ord($str[$i]) - ord($nk[$i]) + 0x30);

		}

		return str_replace(' ', '', substr($out_nk, 0, $str_len));
	}

	/** 
	 * Login to Novaworld
	 *
	 * @param	string $user - Novaworld Username
	 * @param	string $pass - Novaworld Password
	 * @param	int $throttle - Force timeout between retrieveData requests
	 * @param	int $curl_timeout - cURL timeout
	 * @return	array - Cookies -> (array) Cookie Data, Result -> (string) Page Data
	 *
	 */
	public function nwLogin(string $user, string $pass, int $throttle = 500, int $curl_timeout = 5) : array {

		$this->lobby['LoginData']['Name'] = $user;
		$this->lobby['LoginData']['Password'] = $pass;

		$login = $this->retrieveData($this->lobby['LoginUrl'], array(), $this->lobby['LoginData'], $throttle, $curl_timeout);

		$login_redirect = $this->retrieveData($this->lobby['LoginUrl'], $login['Cookies'], array(), $throttle, $curl_timeout);

		$login_result = $this->retrieveData($this->lobby['LoginUrl'], $login['Cookies'], array(), $throttle, $curl_timeout);

		$this->lobby_cookies = $login_result['Cookies'];

		return $login_result;
	}

	/** 
	 * Scrape the server page for NK/CK etc
	 *
	 * @param	bool $rid - Server's RID
	 * @param	int $throttle - Force timeout between retrieveData requests
	 * @param	int $curl_timeout - cURL timeout
	 * @return	array - Server (NK, CK, ...)
	 *
	 */
	public function nwServerExtract(int $rid, int $throttle = 500, int $curl_timeout = 5) : array {

		$server_join = $this->retrieveData($this->lobby['JoinString'].$rid, $this->lobby_cookies, array(), $throttle, $curl_timeout);

		$server_join_result = $this->retrieveData($this->lobby['JoinUrl'], array_merge($this->lobby_cookies, $server_join['Cookies']), array(), $throttle, $curl_timeout);

		//###############################################
		if(preg_match('/\[(.*?)\]/i', $server_join_result['Result'], $title_match) == 1) {

			parse_str($title_match[1], $output);

			if(!empty($output['NK'])) {

				$ip_port = explode(':', $this->nk2string($output['NK']));

				$output['Port'] = !empty($ip_port[1]) ? $ip_port[1] : 0;

			}

			return $output;
		}

		return array();
	}

	/** 
	 * Retrieves data from a webpage
	 *
	 * @param	string $url - The url of the website
	 * @param	array $cookie_data - Cookie / Session data
	 * @param	array $post_vars - HTTP POST vars to send
	 * @param	int $throttle - Force timeout between retrieveData requests
	 * @param	int $curl_timeout - cURL timeout
	 * @return	array - Cookies -> (array)Cookie Data, Result -> (string)Page Data
	 *
	 */
	private function retrieveData(string $url, array $cookie_data, array $post_vars, int $throttle, int $curl_timeout = 5) : array {

		$ch = curl_init();

		// Setup verbose output
		curl_setopt($ch, CURLOPT_VERBOSE, true);
		$verbose_output = fopen('php://temp', 'w+');
		curl_setopt($ch, CURLOPT_STDERR, $verbose_output);

		// Set url and user-agent
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_USERAGENT, $this->lobby['UserAgent']);

		// Send cookies if available
		if(!empty($cookie_data))
			curl_setopt($ch, CURLOPT_COOKIE, http_build_query($cookie_data, '', '; '));

		// Set requset method to post and setup fields
		if(!empty($post_vars)) {

			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_vars));

		}

		// Send curl request
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $curl_timeout);
		$result = curl_exec($ch);
		curl_close($ch);

		// Rewind to retrive the full curl output
		rewind($verbose_output);
		$verbose_log = stream_get_contents($verbose_output);

		// Remove excessive verbose included from curl build
		$verbose_lines = explode("\n", $verbose_log);
		$verbose_trimmed = array();
		foreach($verbose_lines AS $line) {

			// Bug in curl build including excessive lines?
			if (strpos($line, 'ms for 1 (transfer') !== FALSE)
				continue;

			$verbose_trimmed[] = $line;

		}

		$verbose_trimmed = implode("\n", $verbose_trimmed);

		// Find all cookies
		preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $result, $cookie_matches);

		//Build cookie data array
		$cookie_data_received = array();
		foreach($cookie_matches[1] AS $cookie_line) {

			parse_str($cookie_line, $cookie);
			$cookie_data_received = array_merge($cookie_data_received, $cookie);

		}

		// Save this request for debug
		$this->lobby_verbose[] = array(
			'Url' => $url,
			'Page_Data' => htmlspecialchars($result),
			'Post_Vars' => $post_vars,
			'Cookies_Sent' => $cookie_data,
			'Cookies_Received' => $cookie_data_received,
			'Curl_Log' => $verbose_trimmed,
		);

		// Throttle
		usleep($throttle);

		// Return data
		return array(
			'Cookies' => $cookie_data_received,
			'Result' => $result,
		);

	}

	/** 
	 * Returns array of verbose output from connecting to the lobby via cURL
	 * @return	array - cURL verbose output
	 */
	public function lobbyVerbose() : array {

		return $this->lobby_verbose;
		
	}

	/** 
	 * Opens GLB from uri
	 *
	 * @param	string $uri - The location of the file
	 * @return	string - GLB Raw data
	 *
	 */
	public function glbOpen(string $uri) : string {

		$glb = '';

		if(($handle = @fopen($uri, 'rb')) !== false){

			while(!feof($handle))
				$glb .= fread($handle, 8192);

			fclose($handle);

		} else {

			$this->glb_errors[] = 'openGLB -> Could not open uri: '.$uri;
			$this->glb_errors[] = 'You may need to login with nwLogin first';
			$this->glb_errors[] = $http_response_header;

		}

		return $glb;
	}

	/** 
	 * Decrypts $glb from openGLB()
	 *
	 * @param	string $glb - Raw GLB data
	 * @return	string - Decrypted GLB data
	 *
	 */
	public function glbDecrypt($glb) : string {

		$glb_decrypted = '';

		$constdec = array(
			112, 
			222, 
			76, 
			186, 
			40, 
			150, 
			4
		);

		$multi = 0xA0C2;
		$key = 'NOVAWORLD';
		$rconst = 0;
		$rkey = 0;
		$x = 0;
		$len = strlen($glb);

		// if data length is 0, something went wrong
		if(!$len) {

			$this->glb_errors[] = 'decryptGLB -> strlen(glb) was empty.';
			return '';

		}

		for($i=0; $i < $len; $i++){

			if ($rconst > 6) {

				$rconst = 0;
				$x++;

			}

			if ($rkey >= strlen($key)) 
				$rkey = 0;

			$lowbase = 0x4B05731 * $multi + 1 & 0xFFFF;

			$multi = $lowbase;

			$ord = ord($glb[$i]) - ord($key[$rkey]) + $constdec[$rconst] + ($x * 2) - $lowbase & 0xFF;

			$chr = chr($ord);

			$glb_decrypted .= $chr;

			$rkey++;
			$rconst++;

		}

		return $glb_decrypted;
	}

	/** 
	 * Decodes $glb from decryptGLB(), returns array of strings
	 *
	 * @param	string $glb - Decrypted GLB data
	 * @return	array - Decoded GLB data (array of chr)
	 *
	 */
	public function glbDecode($glb) : array {

		if(!strlen($glb)) {

			$this->glb_errors[] = 'decodeGLB -> glb length was zero.';
			return array();

		}

		$glb_array = str_split($glb);

		// Locate the first occurence of a string pattern to find the base offset
		$offset = $this->findPatternOffset($glb, $this->pattern_data) - strlen($this->pattern_data);

		if($offset < 0) {

			$this->glb_errors[] = 'decodeGLB -> offset to start from could not be located.';
			return array();

		}

		$offset += $this->glb_server_offset;

		$glb_size = count($glb_array);

		if(!$glb_size) {

			$this->glb_errors[] = 'decodeGLB -> glb_array was empty.';
			return array();

		}

		// Loop through the server list until we reach the pattern PLYR
		while($offset < $glb_size) {

			if(!$this->decodeServerLine($glb_array, $offset))
				break;

		}

		// Loop through the player list
		while($offset < $glb_size) {

			if(!$this->decodePlayerLine($glb_array, $offset))
				break;

		}

		return $glb_array;
	}

	/**
	 *
	 * Decodes a single server line, starting at $offset
	 *
	 * @param	int $glb_array - Array of strings from decodeGLB
	 * @param	int $offset (by ref) - The offset to start reading from
	 * @return	bool
	 *
	 */
	private function decodeServerLine(array $glb_array, int &$offset) : bool {

		// Reached the player list, server list should be complete
		if($glb_array[$offset] == 'P' && $glb_array[$offset + 1] == 'L' && $glb_array[$offset + 2] == 'Y' && $glb_array[$offset + 3] == 'R')
			return false;

		// Some servers appear empty but have DATA at the offset, move onto the next offset
		if($glb_array[$offset] == 'D' && $glb_array[$offset + 1] == 'A' && $glb_array[$offset + 2] == 'T' && $glb_array[$offset + 3] == 'A')
			$offset += $this->glb_server_offset;

		// Server array
		$server = array();

		// Offset
		// $server['Start_Offset'] = $offset;

		// RID (Int32)
		$server['RID'] = 0;
		for($n = 0; $n < 4; $n++) {

			$server['RID'] |= ord($glb_array[$offset]) << ($n * 8);
			$offset++;

		}

		// IP Address
		$server['IPAddress'] = ord($glb_array[$offset]).".".ord($glb_array[$offset + 1]).".".ord($glb_array[$offset + 2]).".".ord($glb_array[$offset + 3]);

		// IP + 4 unknown bytes
		$offset += 8;

		// Server Name
		$server['Name'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Name'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// GameType
		$server['GameType'] = '';
		while($glb_array[$offset] != "\0") {
			$server['GameType'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// MapName
		$server['MapName'] = '';
		while($glb_array[$offset] != "\0") {
			$server['MapName'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Region
		$server['Region'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Region'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Players
		$server['Players'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Players'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// MaxPlayers
		$server['MaxPlayers'] = '';
		while($glb_array[$offset] != "\0") {
			$server['MaxPlayers'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Dedicated
		$server['Dedicated'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Dedicated'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// TimeLeft
		$server['TimeLeft'] = '';
		while($glb_array[$offset] != "\0") {
			$server['TimeLeft'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Password
		$server['Password'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Password'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Country
		$server['Country'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Country'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Message
		$server['Message'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Message'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Age
		$server['Age'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Age'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// TimeOfDay
		$server['TimeOfDay'] = '';
		while($glb_array[$offset] != "\0") {
			$server['TimeOfDay'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Stat
		$server['Stat'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Stat'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Level
		$server['Level'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Level'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Locked
		$server['Locked'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Locked'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Tracers
		$server['Tracers'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Tracers'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Skins
		$server['Skins'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Skins'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// BBMode
		$server['BBMode'] = '';
		while($glb_array[$offset] != "\0") {
			$server['BBMode'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Mods
		$server['Mods'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Mods'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Pix
		$server['Pix'] = '';
		while($glb_array[$offset] != "\0") {
			$server['Pix'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// BHDExp1
		$server['BHDExp1'] = '';
		while($glb_array[$offset] != "\0") {
			$server['BHDExp1'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// BHDExp2
		$server['BHDExp2'] = '';
		while($glb_array[$offset] != "\0") {
			$server['BHDExp2'] .= $glb_array[$offset];
			$offset++;
		}
		$offset++;

		// Containers for data retrieved later
		$server['PlayerList'] = array();
		$server['Port'] = '';
		$server['NK'] = '';
		$server['CK'] = '';
		$server['NI'] = '';
		$server['NP'] = '';
		$server['BK'] = '';

		// Add server details to the master list
		$this->server_list[$server['RID']] = $server;

	    return true;
	}

	/**
	 *
	 * Decodes player list, starting at $offset
	 *
	 * @param	int $glb_array - Array of strings from decodeGLB
	 * @param	int $offset (by ref) - The offset to start reading from
	 * @return	bool
	 *
	 */
	private function decodePlayerLine(array $glb_array, int &$offset) : bool {

		// End of the file reached
		if($glb_array[$offset] == "\0" && $glb_array[$offset + 1] == "\0" && $glb_array[$offset + 2] == "\0")
			return false;

		// Next list detected
		if(!($glb_array[$offset] == 'P' && $glb_array[$offset + 1] == 'L' && $glb_array[$offset + 2] == 'Y' && $glb_array[$offset + 3] == 'R'))
			return false;

		// PLYR + 4 unknown bytes
		$offset += 8; 

		// RID (Int32)
		$rid = 0;
		for($n = 0; $n < 4; $n++) {

			$rid |= ord($glb_array[$offset]) << ($n * 8);
			$offset++;

		}

		// Player Lines (Int32)
		$player_count = 0;
		for($n = 0; $n < 4; $n++) {

			$player_count |= ord($glb_array[$offset]) << ($n * 8);
			$offset++;

		}

		// Player list array
		$players = array();
		for($n = 0; $n < $player_count; $n++) {

			//Player Name
			$player_name = '';
			while($glb_array[$offset] != "\0") {

				$player_name .= $glb_array[$offset];
				$offset++;

			}

			$players[] = $player_name;

			$offset++;

		}

		//Add it to the server if the rid exists
		if(array_key_exists($rid, $this->server_list)) 
			$this->server_list[$rid]['PlayerList'] = $players;

		return true;
	}

	/** 
	 * Updates the server list with the data from nwServerExtract
 	 * @param	int $rid - Servers RID
 	 * @param	array $append - Data to append to the server
	 * @return	bool
	 */
	public function glbUpdateServer(int $rid, array $append) : bool {

		// Add it to the server if the rid exists
		if(!$rid || !array_key_exists($rid, $this->server_list)) 
			return false;

		$this->server_list[$rid] = array_merge($this->server_list[$rid], $append);
		
		return true;
	}

	/** 
	 * Returns the server list array
	 * @return	array - List of servers
	 */
	public function glbServerList() : array {

		return $this->server_list;
		
	}

	/** 
	 * Returns array of errors in the glb open/decrypt/decode process
	 * @return	array - GLB Errors
	 */
	public function glbErrors() : array {

		return $this->glb_errors;
		
	}

	/** 
	 * Prints the server list in JSON format. 
	 *
	 * @param	bool $pretty - JSON_PRETTY_PRINT
	 *
	 */
	public function printJsonServerList(bool $pretty = false) : void {

		print json_encode($this->server_list, $pretty ? JSON_PRETTY_PRINT : false);
		
	}

	/** 
	 * Removes ~# from server's name
	 *
	 * @param	bool $pretty - JSON_PRETTY_PRINT
	 *
	 */
	public static function removeTilde(string $str) : string {

		return preg_replace("/~([0-9])/", "", $str);

	}

	/**
	 *
	 * Finds an offset from pattern
	 *
	 * @param	string $string - The string to search
	 * @param	string $pattern - The pattern to search for
	 * @return	int - Offset
	 *
	 */
	public static function findPatternOffset(string $string, string $pattern) : int {

		$pos = strpos($string, $pattern) + strlen($pattern);

		return $pos === false ? -1 : $pos;

	}

}
