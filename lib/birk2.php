<?php
error_reporting(E_ALL);
$root = dirname(__DIR__);

set_include_path("$root/local/:$root/library/");
spl_autoload_register();

/*
    - (de)birkify - only for entityIDs and ACSs
*/

$config = <<<EOF
instance               = birk
schemapath       = '/home/ndn-wayf/birk.wayf.dk/schemas/'

birkifypatterns[]      = '/^(https?:\/\/)(.*)$/'
birkifypatterns[]      = '/^(?!https?:\/\/)(.*)/'
birkifyreplacements[]  = '$1birk.wayf.dk/birk.php/$2'
birkifyreplacements[]  = 'urn:oid:1.3.6.1.4.1.39153:42:$1'
debirkifypatterns[]    = '/birk\.wayf\.dk\/birk.php\//'
debirkifypatterns[]    = '/^urn:oid:1.3.6.1.4.1.39153:42:/'
hubSSO                 = 'https://wayf.wayf.dk/saml2/idp/SSOService.php'
privatekey             = 'hsm:abc:http://localhost ...'
hsmtoken               = 'abcdef'
selfsigneddigestMethod = 'sha256'
metadataprovider = file
cacheduration	 = 'P7D'

sources[0-w-idp] = 'https://wayf.wayf.dk/saml2/idp/metadata.php'
sources[1-b-idp] = 'https://metadata.wayf.dk/birk-idp.xml'
sources[2-hub-sp] = 'https://janus.wayf.dk/module.php/janus/metadataexport.php?id=prod-sp-xml'
sources[3-if-sp] = 'https://metadata.wayf.dk/wayf-prod-sp-delta.xml'
sources[6-pd-sp] = 'https://metadata.wayf.dk/birk-sp-proxy.xml'

[metadata]
path     = '/home/ndn-wayf/birk.wayf.dk/metadata/birk/'
mdqurl   = 'https://phph.wayf.dk/MDQ/BIRK-OPS/entities/{sha1}'


EOF;

$birk2 = new birk2(parse_ini_string($config, true));

$birk2->dispatch();

class birk2
{
    private $config;
    private $mdprovider;
    private $logtag;

	public function __construct($config)
	{
        $this->config = $config;
        $this->mdprovider = new cortometadata($config, $this);
        $this->logtag = time();
    }

    function dispatch()
    {
        if (isset($_GET['SAMLRequest'])) { $this->handle_request(); }
        elseif (isset($_POST['SAMLResponse'])) { $this->handle_response(); }
        else { trigger_error('Could not guess binding, looked for SAMLRequest (GET), SAMLResponse (POST)', E_USER_ERROR); }
    }

    function handle_request()
    {
        $url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
        // lookup up self or extract idpprovder from location - debirkify self
        list($entityID, $dummy) = $this->mdprovider->readMD($url, true);
        if (!$entityID) { trigger_error("could not find entityID - tried looking up: '%s'", $url, E_USER_ERROR); }

        $xp = xp::xpFromString(gzinflate(base64_decode($_GET['SAMLRequest'])));
//         $errors = $this->verifySchema($xp, 'saml-schema-protocol-2.0.xsd');
//         $this->fatalIf($errors, "SAMLMessage does not validate according to schema: , error(s): %s",
//                                 join(', ', array_map(function($a) { return "line: {$a->line}:{$a->column}, error: {$a->message}";}, $errors)));

        // birkify AssertionConsumerURL or else give up
        $acsurl = $xp->query('/samlp:AuthnRequest/@AssertionConsumerServiceURL')->item(0);
        $protocolbinding = $xp->query('/samlp:AuthnRequest/@ProtocolBinding')->item(0);

        if ($acsurl === null || $protocolbinding === null || $protocolbinding->nodeValue != 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') { trigger_error('not a valid request', E_USER_ERROR); }
        // add a acs url that points back to us
        $acsurl->nodeValue = $this->birkify($acsurl->nodeValue);

        // put idprovider into Scoping element
        softquery::query($xp, $xp->document, '/samlp:AuthnRequest/samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID', $this->debirkify($entityID), null, true);

        // put hub sso into destination
        $destination = $xp->query('/samlp:AuthnRequest/@Destination')->item(0);
        if ($destination === null) { trigger_error('no destination', E_USER_ERROR); }

        $destination->nodeValue =  $this->config['hubSSO'];

        $location =  $this->config['hubSSO'] . '?SAMLRequest=' . urlencode(base64_encode(gzdeflate($xp->document->saveXML())))
            . (isset($_GET['RelayState']) ? '&RelayState=' . urlencode($_GET['RelayState']) : '');

        // redirect to destination
        header('Location: ' . $location);
        exit;
    }

    function handle_response()
    {
        $xp = $this->xpath(base64_decode($_POST['SAMLResponse']));
        // check signature from wayf both response and assertion

        // replace destination with debirkifyed destination
        $destination = $xp->query('/saml:Destination')->item(0);
        if ($destination === null) { trigger_error('no destination', E_USER_ERROR); }
        $destination->nodeValue = $this->debirkify($destination->nodeValue);

        // replace issuer with birkified authenticatingauthority
        $issuer = $xp->query('Issuer')->item(0);
        if ($issue === null) { trigger_error('no issuer', E_USER_ERROR); }
        $authenticatingauthority = $xp->query('authenticatingauthority')->item(0);
        if ($authenticatingauthority === null) { trigger_error('no authenticatingauthority', E_USER_ERROR); }
        $issuer->nodevalue = $this->birkify($authenticatingauthority->nodeValue);
        // sign
        pseudoca::setprivatekey($this->config['privatekey'], $this->config['selfsigneddigestMethod']);
        $certificate = pseudoca::selfsign($issuer->nodevalue); // birkified currently - non-birkified in phph generated md

        $message = $xp->document->saveXML();
        $this->sign($this->config['privatekey'], $certificate, $message, true);
        // post to destination

        $formparams = array(
                'action' => $destination->nodeValue,
                'message' => base64_encode($message),
                'xtra' => isset($_POST['RelayState']) ? '<input type="hidden" name="RelayState" value="' . htmlspecialchars($_POST['RelayState']) . '">' : '',
        );
        print $this->renderTemplate('form', $formparams);
        exit;
    }

	function birkify($uri)
	{
        return preg_replace($this->config['birkifypatterns'], $this->config['birkifyreplacements'], $uri, 1);
	}

	function debirkify($uri)
	{
        return preg_replace($this->config['debirkifypatterns'], '', $uri, 1);
	}
}
