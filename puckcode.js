//Turns a hex string into a byte array
function parseHexString(str) 
{ 
    var result = [];
    while (str.length >= 2) 
    { 
        result.push(parseInt(str.substring(0, 2), 16));

        str = str.substring(2, str.length);
    }

    return result;
}

//Turns a byte array into a hex string
function createHexString(arr) {
    var result = "";
    var z;

    for (var i = 0; i < arr.length; i++) {
        var str = arr[i].toString(16);

        z = 2 - str.length + 1;
        str = Array(z).join("0") + str;

        result += str;
    }

    return result;
}

//Changes the key being advertised to the argument passed in
//Takes UInt8Array
function setAdvertising(keybytes){
  
  //1f is the length of the message (30 bytes)
  //ff is the message type (manufacturer data) [1 byte]
  //One byte of the key stored in the company ID [1 byte]
  //0f is the company id (outside range of assigned IDs) [1 bytes]
  //Followed by zeroes [27 bytes]
  data = "1eff000f000000000000000000000000000000000000000000000000000000";
  
  //Convert to byte array to add in our key bytes
  databytes = parseHexString(data);
  console.log(createHexString(keybytes));
  
  //Replaces zeroes with key bytes
  databytes[2] = keybytes[0];
  for(x = 4; x < 31; x++){
    databytes[x] = keybytes[x-3];
  }
  
  NRF.setTxPower(4);
  
  console.log(createHexString(databytes));
  
  //Set advertising
  NRF.setAdvertising(databytes,
  {"showName": false, "interval": 1000, "connectable": false});
  
}

//Rotates to the next key from our key file
function rotateKey(){
  key = Uint8Array(keyblob, index * 28, 28);
  setAdvertising(key);
  index += 1;
  if(index == numkeys){
    index = 0;
  }
}

function blink(){
  digitalWrite(LED1, 1);
  setTimeout("digitalWrite(LED1, 0)", 2000);
}

index = 0;

//Read key data from puckkeys.bin file
keyblob = require("Storage").readArrayBuffer("puckkeys.bin");

if(keyblob == undefined){
  console.log("No key file");
}
else
{
  numkeys = keyblob.length / 28;
  
  //Start broadcasting keys after 10 seconds
  setTimeout(rotateKey, 10000);
  //Rotate keys every 24 hours
  setInterval(rotateKey, 86400000);
  //Set blink function to BTN1 so we know if the program is still running
  setWatch(blink, BTN1, {repeat: true, edge: "rising"});
}