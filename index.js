function interpret() {
  var hexinput = document.getElementById('hexinput').value.toUpperCase().replace(/\s/g, '');
  var hextest = /[0-9A-Fa-f]/g;
  var starttest = /^1[4-7]/;

  if (hexinput.length == 0) {
    showError("Please enter a hex byte array.");
  } else if (!hextest.test(hexinput)) {
    showError("Input has invalid characters.");
  } else if ((hexinput.length % 2) != 0) {
    showError("Input is missing a character.");
  } else if (!starttest.test(hexinput)) {
    showError("Valid starting bytes should start with 14-17.");
  } else {
    // format input 
    var bytes = hexinput.match(/.{2}/g);
    document.getElementById('hexinput').value = bytes.map(item => item + " ").join('');

    var output = document.getElementById('output');
    output.innerHTML = "";

    var header = document.createElement('h3');
    header.innerHTML = "Interpretation";
    output.appendChild(header);

    var table = document.createElement('table');
    var tableHead = document.createElement('thead');
    var tableHeadRowRawBytes = document.createElement('th');
    var tableHeadRowTag = document.createElement('th');
    var tableHeadRowInterpretation = document.createElement('th');
    var tableHeadRowInfo = document.createElement('th');

    var tableBody = document.createElement('tbody');

    tableHeadRowRawBytes.innerHTML = "Raw Bytes";
    tableHeadRowTag.innerHTML = "Tag";
    tableHeadRowInterpretation.innerHTML = "Interpretation";
    tableHeadRowInfo.innerHTML = "Details";

    table.appendChild(tableHead);
    tableHead.appendChild(tableHeadRowRawBytes);
    tableHead.appendChild(tableHeadRowTag);
    tableHead.appendChild(tableHeadRowInterpretation);
    tableHead.appendChild(tableHeadRowInfo);
    table.appendChild(tableBody);


    interpretBytes(bytes).forEach(element => {
      var row = document.createElement('tr');
      var bytes = document.createElement('td');
      var tag = document.createElement('td');
      var interpretation = document.createElement('td');
      var info = document.createElement('td');


      bytes.innerHTML = element.raw_bytes;
      tag.innerHTML = element.tag;
      interpretation.innerHTML = element.interpretation;
      info.innerHTML = element.info != null ? element.info : 'N/A';

      row.appendChild(bytes);
      row.appendChild(tag);
      row.appendChild(interpretation);
      row.appendChild(info);

      tableBody.appendChild(row);
    });

    output.appendChild(table);
  }
}

function interpretBytes(bytes) {
  var interpretationArray = [];

  var CHANGE_CIPHER_SPEC = '14';
  var ALERT = '15';
  var HANDSHAKE = '16';
  var APPLICATION_DATA = '17';
  var PROTOCOL_TAG = 'Record Protocol';

  var protocol = bytes[0];
  if (protocol == CHANGE_CIPHER_SPEC) {
    interpretationArray.push({
      raw_bytes: protocol, tag: PROTOCOL_TAG, interpretation: 'Change Cipher Spec', info: 'Negotiated parameters take effect'
    });
  } else if (protocol == ALERT) {
    interpretationArray.push({ raw_bytes: protocol, tag: PROTOCOL_TAG, interpretation: 'Alert', info: 'Indicates compromised security' });
  } else if (protocol == HANDSHAKE) {
    interpretationArray.push({ raw_bytes: protocol, tag: PROTOCOL_TAG, interpretation: 'Handshake', info: 'Peers authenticate and negotiate the parameters' });
  } else if (protocol == APPLICATION_DATA) {
    interpretationArray.push({ raw_bytes: protocol, tag: PROTOCOL_TAG, interpretation: 'Application Data', info: 'Arbitrary data is in the secure channel' });
  } else {
    interpretationArray.push({ raw_bytes: protocol, tag: PROTOCOL_TAG, interpretation: 'Unknown', info: 'No information' });
  }

  interpretationArray = interpretationArray.concat(interpretSSLTLSVersion(bytes.slice(1, 3)));

  var lengthString = bytes[3] + ' ' + bytes[4];
  var length = parseInt(bytes[3] + '' + bytes[4], 16)
  interpretationArray.push({ raw_bytes: lengthString, tag: 'Protocol Length', interpretation: length.toString() + ' bytes', info: 'Length of the protocol layer' });

  if (protocol == HANDSHAKE) {
    interpretationArray = interpretationArray.concat(interpretHandshakeProtocol(bytes.slice(5, length + 5)));
  }

  return interpretationArray;
}

function interpretHandshakeProtocol(bytes) {
  var interpretationArray = [];

  var HELLO_REQUEST = '00';
  var CLIENT_HELLO = '01';
  var SERVER_HELLO = '02';
  var CERTIFICATE = '0B';
  var SERVER_KEY_EXCHANGE = '0C';
  var CERTIFICATE_REQUEST = '0D';
  var SERVER_DONE = '0E';
  var CERTIFICATE_VERIFY = '0F';
  var CLIENT_KEY_EXCHANGE = '10';
  var FINISHED = '14';
  var HANDSHAKE_TYPE_TAG = 'Handshake Type';

  var helloLengthString = bytes.slice(1, 4).map(item => item + ' ').join('');
  var helloLength = parseInt(bytes.slice(1, 4).join(''), 16)
  var HANDSHAKE_LENGTH_TAG = 'Handshake Length';

  var type = bytes[0];
  if (type == HELLO_REQUEST) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Hello Request', info: 'Server restarts the handshake negotiation' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == CLIENT_HELLO) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Client Hello', info: 'Begins TLS handshake negotiation' }); interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
    bytes.splice(0, 4);
    var version = bytes.splice(0, 2);
    interpretationArray = interpretationArray.concat(interpretSSLTLSVersion(version, 'Handshake Version'));

    var random = bytes.splice(0, 4);
    interpretationArray.push({ raw_bytes: random.map(item => item + ' ').join(''), tag: '32-bit Random', interpretation: '4 bytes' });

    var sessionIdLength = bytes.splice(0, 1);
    interpretationArray.push({ raw_bytes: sessionIdLength, tag: 'Session Id Length', interpretation: parseInt(sessionIdLength, 16).toString() + ' bytes' });

    var sessionId = bytes.splice(0, parseInt(sessionIdLength, 16));
    interpretationArray.push({ raw_bytes: sessionId.map(item => item + ' ').join(''), tag: 'Session Id', interpretation: 'Uninterpreted bytes' });

    var cipherSuitesLength = bytes.splice(0, 2);
    interpretationArray.push({ raw_bytes: cipherSuitesLength.map(item => item + ' ').join(''), tag: 'Cipher Suite Length', interpretation: parseInt(cipherSuitesLength, 16).toString() + ' bytes' });

    var cipherIds = bytes.splice(0, parseInt(cipherSuitesLength, 16));
    for (var count = 0; count < cipherIds.length; count++) {
      interpretationArray.push({ raw_bytes: cipherIds[count], tag: 'Cipher Id ' + (count + 1), interpretation: 'Refer to https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv' });
    }

    var compressionMethodsLength = bytes.splice(0, 2);
    interpretationArray.push({ raw_bytes: compressionMethodsLength.map(item => item + ' ').join(''), tag: 'Compression Methods Length', interpretation: parseInt(compressionMethodsLength, 16).toString() + ' bytes' });

    var compressionMethods = bytes.splice(0, parseInt(compressionMethodsLength, 16));
    interpretationArray.push({ raw_bytes: compressionMethods.map(item => item + ' ').join(''), tag: 'Compression Methods', interpretation: 'Uninterpreted bytes' });

    var extensionsLength = bytes.splice(0, 2);
    interpretationArray.push({ raw_bytes: extensionsLength.map(item => item + ' ').join(''), tag: 'Extensions Length', interpretation: parseInt(extensionsLength, 16).toString() + ' bytes' });

    var extensions = bytes.splice(0, parseInt(extensionsLength, 16));
    interpretationArray.push({ raw_bytes: extensions.map(item => item + ' ').join(''), tag: 'Extensions', interpretation: 'Uninterpreted bytes' });

  } else if (type == SERVER_HELLO) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Server Hello', info: 'Server\'s response to the Client Hello' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == CERTIFICATE) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Certificate', info: 'The body of this message contains a chain of certificates' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == SERVER_KEY_EXCHANGE) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Server Key Exchange', info: 'Server provides algorithm parameters to the client' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == CERTIFICATE_REQUEST) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Certificate Request', info: 'Server requires client identity authentication' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == SERVER_DONE) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Server Done', info: 'Finishes the server part of the handshake negotiation' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == CERTIFICATE_VERIFY) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Certificate Verify', info: 'Client proves it possesses the private key' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == CLIENT_KEY_EXCHANGE) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Client Key Exchange', info: 'Client provides server data to generate keys' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else if (type == FINISHED) {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Finished', info: ' TLS negotiation is complete and the CipherSuite is activated' });
    interpretationArray.push({ raw_bytes: helloLengthString, tag: HANDSHAKE_LENGTH_TAG, interpretation: helloLength.toString() + ' bytes', info: 'Length of the handshake layer' });
  } else {
    interpretationArray.push({ raw_bytes: type, tag: HANDSHAKE_TYPE_TAG, interpretation: 'Unknown', info: 'No information' });
  }

  return interpretationArray;
}

function interpretSSLTLSVersion(bytes, tag) {
  var interpretationArray = [];

  var SSL_3_0 = '03 00';
  var TLS_1_0 = '03 01';
  var TLS_1_1 = '03 01';
  var TLS_1_2 = '03 02';
  var TLS_1_3 = '03 03';
  var VERSION_TAG = tag == undefined ? 'SSL/TLS Version' : tag;

  var version = bytes[0] + ' ' + bytes[1];
  if (version == SSL_3_0) {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'SSL 3.0' });
  } else if (version == TLS_1_0) {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'TLS 1.0' });
  } else if (version == TLS_1_1) {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'TLS 1.1' });
  } else if (version == TLS_1_2) {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'TLS 1.2' });
  } else if (version == TLS_1_3) {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'TLS 1.3' });
  } else {
    interpretationArray.push({ raw_bytes: version, tag: VERSION_TAG, interpretation: 'Unknown', info: 'No information' });
  }

  return interpretationArray;
}

function showError(errorString) {
  // clear all children 
  document.getElementById('output').innerHTML = "";
  var error = document.createElement('p');
  addClass(error, 'error');
  error.innerHTML = errorString;
  document.getElementById('output').appendChild(error);
}


function hasClass(el, className) {
  if (el.classList)
    return el.classList.contains(className);
  return !!el.className.match(new RegExp('(\\s|^)' + className + '(\\s|$)'));
}

function addClass(el, className) {
  if (el.classList)
    el.classList.add(className)
  else if (!hasClass(el, className))
    el.className += " " + className;
}

function removeClass(el, className) {
  if (el.classList)
    el.classList.remove(className)
  else if (hasClass(el, className)) {
    var reg = new RegExp('(\\s|^)' + className + '(\\s|$)');
    el.className = el.className.replace(reg, ' ');
  }
}

function erase() {
  document.getElementById('hexinput').value = "";
  document.getElementById('output').innerHTML = "";
}