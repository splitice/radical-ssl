<?php
namespace Radical\Utility\SSL;


use phpseclib\File\X509;

class X509Certificate
{
	private $x509;
	private $cert_data;

	function __construct($data, X509 $x509 = null)
	{
		$this->x509 = new X509();
		if($x509) {
			$this->x509->CAs = $x509->CAs;
		}

		$this->cert_data = $this->x509->loadX509($data);
	}



	function getSubject(){
		return $this->cert_data['tbsCertificate']['subject'];
	}

	public function getExtension($name){
		foreach ($this->cert_data['tbsCertificate']['extensions'] as $extension) {
			if ($extension['extnId'] == $name){
				return $extension['extnValue'];
			}
		}

	}

	function isSigned(){
		return $this->x509->validateSignature();
	}

	/**
	 * Get the URL of the parent certificate.
	 *
	 * @return string
	 */
	public function getParentCertificateURL()
	{
		foreach ($this->getExtension('id-pe-authorityInfoAccess') as $extnValue) {
			if ($extnValue['accessMethod'] == 'id-ad-caIssuers') {
				return $extnValue['accessLocation']['uniformResourceIdentifier'];
			}
		}
	}

	function getContents(){
		return $this->x509->saveX509($this->cert_data)."\r\n";
	}
}