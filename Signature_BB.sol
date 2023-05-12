// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/* Verificación de una firma 

¿Cómo firmar y verificar?
#Procedimiento para firmar
1. Crear un mensaje para firmar, en este caso una credencial verificable.
2. Crear el hash del mensaje
3. Firmar el hash (fuera de la cadena, mantén tu llave privada secreta)

#Verificando la firma
1. Recrear el hash del mensaje original
2. Recuperar el firmante de la firma y el hash
3. Comparar el firmante recuperado con el firmante reclamado
*/

contract VerificaFirma{

    /* 1. Desbloquear la cuenta de Metamask 
    ethereum.enable()
    */

    /* 2. Obtener hash del mensaje para firmar
    getMessageHash(0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C,123,"Mensaje",1)

    hash = "0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd"
    */

    function getHashMensaje(
        address _para,
        uint _cantidad,
        string memory _mensaje,
        uint _nonce //(Number only used once. Un número aleatorio usado una sola 
        //vez destinado a la autenticación de transferencia de datos entre dos o más partes.
    )public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_para, _cantidad, _mensaje, _nonce));
    }

    /* 3. Firmar el hash del mensaje
    # usando el navegador
    cuenta = "copiar y pegar la cuenta del firmante"
    ethereum.request({ method: "firma_personal", params: [cuenta, hash]}).then(console.log)

    # usando la web3
    web3.personal.sign(hash, web3.eth.defaultAccount, console.log)

    La firma será diferente para diferentes cuentas
    0x993dab3dd91f5c6dc28e17439be475478f5635c92a56e17e82349d3fb2f166196f466c0b4e0c146f285204f0dcb13e5ae67bc33f4b888ec32dfe0a063e8f3f781b
    */

    function getEthMsjHashFirmado(
        bytes32 _HashMensaje
    ) public pure returns (bytes32) {
        /*
        La firma se produce firmando un hash keccak256 con el siguiente formato:
        "\x19Mensaje firmado de Ethereum\n" + len(mensaje) + mensaje
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Mensaje Firmado:\n32", _HashMensaje)
            );
    }

    /* 4. Verifica firma
    firmante = 0xB273216C05A8c0D4F0a4Dd0d7Bae1D2EfFE636dd
    para = 0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C
    cantidad = 123
    mensaje = "coffee and donuts"
    nonce = 1
    firma =
        0x993dab3dd91f5c6dc28e17439be475478f5635c92a56e17e82349d3fb2f166196f466c0b4e0c146f285204f0dcb13e5ae67bc33f4b888ec32dfe0a063e8f3f781b
    */

    function verifica(
        address _firmante,
        address _para,
        uint _cantidad,
        string memory _mensaje,
        uint _nonce,
        bytes memory firma
    ) public pure returns (bool) {
        bytes32 HashMensaje = getHashMensaje(_para, _cantidad, _mensaje, _nonce);
        bytes32 ethHashMensajeFirmado = getEthMsjHashFirmado(HashMensaje);

        return recuperaFirmante(ethHashMensajeFirmado, firma) == _firmante;
    }

    function recuperaFirmante(
        bytes32 _ethHashMensajeFirmado,
        bytes memory _firma
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitFirma(_firma);

        return ecrecover(_ethHashMensajeFirmado, v, r, s);
    }

     function splitFirma(
        bytes memory firma
    ) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(firma.length == 65, "longitud de firma invalida");

        assembly {
            /*
            Los primeros 32 bytes almacenan la longitud de la firma

            add(firma, 32) = puntero de firma + 32
            efectivamente, salta los primeros 32 bytes de la firma

            mload(p) carga los siguientes 32 bytes comenzando en la dirección de memoria p en la memoria
            */

            // primeros 32 bytes, después del prefijo de longitud
            r := mload(add(firma, 32))
            // Siguientes 32 bytes -> 32+32=64
            s := mload(add(firma, 64))
            // Último byte (primer byte de los siguientes 32 bytes) 64+32=96
            v := byte(0, mload(add(firma, 96)))
        }

        // devuelve implícitamente (r, s, v)
    }

}