<?php
namespace Radical\Utility\SSL;

class X509Helpers {
	function checkPair($cert, $key, $passphrase = null, &$reason = null){
		if(openssl_pkey_get_private($key, $passphrase) === false){
            $reason = 'private key';
			return false;
		}
		if(!openssl_x509_check_private_key($cert, $key)){
            $reason = "does not match";
            return false;
        }
        return true;
	}
	
	function generatePrivateKey(){
		return openssl_pkey_new();
	}

	/**
	 * @param SigningDetails $dn
	 * @param null $privateKey
	 * @param null $privkeypass
	 * @param int $numberofdays
	 * @return array
	 * @throws \Exception
	 */
	function generate(SigningDetails $dn, $privateKey = null, $privkeypass = null, $numberofdays = 365){
		if($privateKey === null){
			$privkey = $this->generatePrivateKey();
		}elseif(is_string($privateKey)){
			$privkey = openssl_pkey_get_private($privateKey);
		}else{
			throw new \Exception('Invalid format for private key');
		}
		
		if(!$privkey){
			throw new \Exception('Invalid private key');
		}
		
		$csr = @openssl_csr_new($dn->toArray(), $privkey);
        if(!$csr){
            throw new \Exception('Failed create signing request. Input likely invalid.');
        }

		$sscert = openssl_csr_sign($csr, null, $privkey, $numberofdays);
        if(!$sscert){
            throw new \Exception('Failed create signing request. Input likely invalid.');
        }

		openssl_x509_export($sscert, $publickey);
		$privatekey = null;
		if(!openssl_pkey_export($privkey, $privatekey, $privkeypass)){
			throw new \Exception('Private key generation failed');
		}
		/*$csrStr = null;
		if(!openssl_csr_export($csr, $csrStr)){
			throw new \Exception('CSR generation failed');
		}*/
		
		return [$publickey, $privatekey];
	}
}