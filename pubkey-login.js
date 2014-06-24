'use strict';

var url = require('url');


var PubKeyLogin = function (options) {
  var self  = this;

  self.store = new options.rdf.LdpStore();
  self.getAssertion = PubKeyLogin.getConnectionAssertion;
  self.validate = PubKeyLogin.validateWebId;
  self.getAgent = PubKeyLogin.getSessionAgent;
  self.setAgent = PubKeyLogin.setSessionAgent;

  if (options == null) {
    options = {};
  }

  if ('store' in options) {
    self.store = options.store;
  }

  if ('getAssertion' in options) {
    self.getAssertion = options.getAssertion;
  }

  if ('validate' in options) {
    self.validate = options.validate;
  }

  if ('setAgent' in options) {
    self.setAgent = options.setAgent;
  }

  self.middleware = function (req, res, next) {
    // already authenticated ?
    if (self.getAgent(req) != null) {
      return next();
    }

    var assertion = self.getAssertion(req);

    if (assertion == null) {
      return next();
    }

    self.validate(assertion, function (agent) {
      self.setAgent(agent, req, res);

      next();
    });
  };

  self.assertionMiddleware = function (req, res) {
    var assertion = self.getAssertion(req);

    res.statusCode = 401; // Unauthorized

    if (assertion != null) {
      res.statusCode = 200; // OK
      res.setHeader('Content-Type', 'application/json');
      res.write(JSON.stringify(assertion));
    }

    res.end();
  };
};


PubKeyLogin.ns = {
  'cert': {
    'exponent': 'http://www.w3.org/ns/auth/cert#exponent',
    'key': 'http://www.w3.org/ns/auth/cert#key',
    'modulus': 'http://www.w3.org/ns/auth/cert#modulus'
  }
};


PubKeyLogin.getConnectionAssertion = function (req) {
  if (!('getPeerCertificate' in req.connection)) {
    return null;
  }

  var assertion = {
    'public-key': req.connection.getPeerCertificate(),
    'principal': {
      '@context': 'https://w3id.org/identity/v1',
      'identity': null
    }
  };

  if ('subjectaltname' in assertion['public-key']) {
    var subjectAlternativeName = assertion['public-key'].subjectaltname
      .split(/\,\s?/)
      .filter(function (s) { return s.indexOf('URI:') === 0; }) // select only URIs
      .map(function (s) { return s.substr(4); }); // remove URI: prefix

    if (subjectAlternativeName.length > 0) {
      assertion.principal.identity = subjectAlternativeName[0];
    }
  }

  return assertion;
};


/*PubKeyLogin.getKeyFromHeader = function(req) {
	if(typeof req.headers['ssl_client_cert'] === 'undefined')
		return null;

	var pem = '-----BEGIN CERTIFICATE-----' +
		req.headers['ssl_client_cert'].replace(/\-{5,}[\w\s]*\-{5,}/g, '').replace(/[^0-9a-zA-Z\/\+\=]/g, '\n') +
		'-----END CERTIFICATE-----';

	forgeCertificate = forge.pki.certificateFromPem(pem);

	var san = forgeCertificate.extensions.filter(function(object) {return object.name == 'subjectAltName';});

	if(san != null)
		san = san[0].value.split(',')[1]; //TODO: check type

	var bigIntegerToString = function(n, r) {
		return forge.jsbn.BigInteger.prototype.toString.bind(n)(r);
	};

	key = {
		"exponent": bigIntegerToString(forgeCertificate.publicKey.e, 16) | 0,
		"modulus": bigIntegerToString(forgeCertificate.publicKey.n, 16),
		"url": san
	};

	return key;
};*/


PubKeyLogin.getSessionAgent = function (req) {
  if ('agent' in req.session) {
    return req.session.agent;
  }

  return null;
};


PubKeyLogin.setSessionAgent = function (agent, req) {
  req.session.agent = agent;
};


PubKeyLogin.validateWebId = function (assertion, callback) {
  if (assertion.principal.identity == null) {
    return callback(null);
  }

  var webid = url.parse(assertion.principal.identity);

  webid.hash = null;
  webid = url.format(webid);

  this.store.graph(webid, function (graph) {
    if (graph == null) {
      return callback(null);
    }

    var
      e = parseInt(assertion['public-key'].exponent, 16) + '',
      m = (assertion['public-key'].modulus + '').toLowerCase(),
      found = false;

    graph.match(assertion.principal.identity, PubKeyLogin.ns.cert.key, null).forEach(function (keyTriple) {
      graph.match(keyTriple.object, PubKeyLogin.ns.cert.exponent, null).forEach(function (eTriple) {
        graph.match(keyTriple.object, PubKeyLogin.ns.cert.modulus, null).forEach(function (mTriple) {
          if (e == eTriple.object.valueOf() && m == mTriple.object.valueOf().toLowerCase()) {
            found = true;
          }
        });
      });
    });

    callback(found ? assertion.principal.identity : null);
  });
};


module.exports = PubKeyLogin;