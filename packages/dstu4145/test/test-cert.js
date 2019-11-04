/* eslint-env mocha */
/* eslint-disable no-underscore-dangle */
const gost89 = require('@1-corp/dstu-gost');
const fs = require('fs');
const jk = require('../lib/index.js');
const strutil = require('../lib/util/str');

/* eslint-disable no-global-assign, no-unused-expressions */
const NOT_RANDOM_32 = Buffer.from('12345678901234567890123456789012');

global.crypto = {
  // Moch random only for testing purposes.
  // SHOULD NOT BE USED IN REAL CODE.
  getRandomValues() {
    return NOT_RANDOM_32;
  },
};
/* eslint-enable no-global-assign, no-unused-expressions */

function repeat(inputStr, times) {
  let ret = '';
  let left = times;
  while (left > 0) {
    ret += inputStr;
    left -= 1;
  }
  return ret;
}

function u(input) {
  return strutil.encodeUtf8Str(input, 'der');
}

describe('Certificate', () => {
  const algo = gost89.compat.algos();
  describe('parse sfs stamp', () => {
    const data = fs.readFileSync(`${__dirname}/data/SFS_1.cer`);
    const cert = jk.Certificate.from_asn1(data);

    it('should parse certificate from binary', () => {
      expect(cert.format).toEqual('x509');
      expect(cert.curve.m).toEqual(257);
      expect(Buffer.from(cert.curve.mod_bits)).toEqual(
        Buffer.from([257, 12, 0])
      );
      expect(cert.pk_data).toEqual([
        '0x2c157a5f',
        '0x17857f3c',
        '0xee0ce4a5',
        '0xbf03a3b',
        '0xcb31f667',
        '0x71224a5',
        '0x31401ac',
        '0xcae8dae1',
        '0x1',
      ]);
      expect(cert.valid.from).toEqual(1478124000000); // UTCTime 2016-11-02 22:00:00 UTC
      expect(cert.valid.to).toEqual(1541196000000); // UTCTime 2018-11-02 22:00:00 UTC
      expect(cert.serial).toEqual(
        295234990915418097076372072606219913778474207744
      );
      expect(cert.signatureAlgorithm).toEqual('Dstu4145le');
      expect(cert.pubkeyAlgorithm).toEqual('Dstu4145le');
      expect(cert.extension.ipn.DRFO).toEqual(null);
      expect(cert.extension.ipn.EDRPOU).toEqual('39292197');

      expect(cert.subject.commonName).toEqual(
        'Державна фіскальна служба України.  ОТРИМАНО'
      );
      expect(cert.subject.organizationName).toEqual(
        'Державна фіскальна служба України'
      );
      expect(cert.subject.countryName).toEqual('UA');
      expect(cert.subject.localityName).toEqual('Київ');
      expect(cert.subject.serialNumber).toEqual('2122385');

      expect(cert.issuer.commonName).toEqual(
        'Акредитований центр сертифікації ключів ІДД ДФС'
      );
      expect(cert.issuer.organizationName).toEqual(
        'Інформаційно-довідковий департамент ДФС'
      );
      expect(cert.issuer.organizationalUnitName).toEqual(
        'Управління (центр) сертифікації ключів ІДД ДФС'
      );
      expect(cert.issuer.countryName).toEqual('UA');
      expect(cert.issuer.localityName).toEqual('Київ');
      expect(cert.issuer.serialNumber).toEqual('UA-39384476');
    });

    it('should make simple representation of certificate', () => {
      const info = cert.as_dict();
      expect(info.subject).toEqual({
        commonName: 'Державна фіскальна служба України.  ОТРИМАНО',
        organizationName: 'Державна фіскальна служба України',
        countryName: 'UA',
        localityName: 'Київ',
        serialNumber: '2122385',
      });
      expect(info.issuer).toEqual({
        commonName: 'Акредитований центр сертифікації ключів ІДД ДФС',
        organizationName: 'Інформаційно-довідковий департамент ДФС',
        organizationalUnitName:
          'Управління (центр) сертифікації ключів ІДД ДФС',
        countryName: 'UA',
        localityName: 'Київ',
        serialNumber: 'UA-39384476',
      });
      expect(info.valid).toEqual({
        from: 1478124000000, // UTCTime 2016-11-02 22:00:00 UTC
        to: 1541196000000, // UTCTime 2018-11-02 22:00:00 UTC
      });
      expect(info.extension.ipn).toEqual({
        EDRPOU: '39292197',
      });
      expect(info.extension.tsp).toEqual('http://acskidd.gov.ua/services/tsp/');
      expect(info.extension.ocsp).toEqual(
        'http://acskidd.gov.ua/services/ocsp/'
      );
      expect(info.extension.issuers).toEqual(
        'http://acskidd.gov.ua/download/certificates/allacskidd.p7b'
      );
      expect(info.extension.keyUsage[3]).toEqual(0xc0); // bin 11
    });

    it('should serialize back', () => {
      const der = cert.to_asn1();
      expect(der).toEqual(data);
    });

    it('should serialize name to asn1', () => {
      const der = cert.name_asn1();
      expect(der.toString('hex')).toEqual(
        data.slice(50, 336 + 4 + 50).toString('hex')
      );
    });

    it('should serialize (bypass cache) back', () => {
      const temp = jk.Certificate.from_asn1(data);
      delete temp._raw;
      const der = temp.to_asn1();
      expect(der).toEqual(data);
    });

    it('should make issuer rdn', () => {
      const rdn = cert.rdnSerial();
      expect(rdn).toEqual(
        '33b6cb7bf721b9ce040000009162200086e34a00' +
          '@organizationName=Інформаційно-довідковий департамент ДФС' +
          '/organizationalUnitName=Управління (центр) сертифікації ключів ІДД ДФС' +
          '/commonName=Акредитований центр сертифікації ключів ІДД ДФС' +
          '/serialNumber=UA-39384476' +
          '/countryName=UA' +
          '/localityName=Київ'
      );
    });
  });

  describe('parse minjust ca', () => {
    const data = fs.readFileSync(`${__dirname}/data/CA-Justice.cer`);
    const cert = jk.Certificate.from_asn1(data);

    it('should parse certificate from binary', () => {
      expect(cert.format).toEqual('x509');
      expect(cert.curve.m).toEqual(257);
      expect(cert.curve.mod_bits).toEqual([257, 12, 0]);
      expect(cert.pk_data).toEqual([
        '0xb59265f0',
        '0xaaf792b8',
        '0xdda16518',
        '0x286cb42b',
        '0x3e1be80f',
        '0x5751c3ac',
        '0xe579a40',
        '0x5002f847',
        '0x1',
      ]);
      expect(cert.valid.from).toEqual(1450447200000); // 2015-12-18 14:00:00
      expect(cert.valid.to).toEqual(1608300000000); // UTCTime 2018-11-02 22:00:00 UTC
      expect(cert.serial).toEqual(
        274130962303897476041362771173503318330938753024
      );
      expect(cert.signatureAlgorithm).toEqual('Dstu4145le');
      expect(cert.pubkeyAlgorithm).toEqual('Dstu4145le');
      expect(cert.extension.ipn).toEqual(null);

      expect(cert.subject.commonName).toEqual('АЦСК органів юстиції України');
      expect(cert.subject.organizationName).toEqual('ДП "НАІС"');
      expect(cert.subject.organizationalUnitName).toEqual(
        'Акредитований центр сертифікації ключів'
      );
      expect(cert.subject.localityName).toEqual('Київ');
      expect(cert.subject.serialNumber).toEqual('UA-39787008-2015');

      expect(cert.issuer.commonName).toEqual(
        'Центральний засвідчувальний орган'
      );
      expect(cert.issuer.organizationName).toEqual(
        'Міністерство юстиції України'
      );
      expect(cert.issuer.organizationalUnitName).toEqual(
        'Адміністратор ІТС ЦЗО'
      );
      expect(cert.issuer.countryName).toEqual('UA');
      expect(cert.issuer.localityName).toEqual('Київ');
      expect(cert.issuer.serialNumber).toEqual('UA-00015622-2012');
    });

    it('should serialize back', () => {
      const der = cert.to_asn1();
      expect(der).toEqual(data);
    });

    it('should make issuer rdn', () => {
      const rdn = cert.rdnSerial();
      expect(rdn).toEqual(
        '3004751def2c78ae010000000100000061000000@' +
          'organizationName=Міністерство юстиції України' +
          '/organizationalUnitName=Адміністратор ІТС ЦЗО' +
          '/commonName=Центральний засвідчувальний орган' +
          '/serialNumber=UA-00015622-2012' +
          '/countryName=UA' +
          '/localityName=Київ'
      );
    });

    it('should make issuer rdn for really long orgname', () => {
      const longName = repeat('ЦЗО!', 100);
      const temp = jk.Certificate.from_asn1(data);
      temp.ob.tbsCertificate.issuer.value[0][0].value = u(longName);

      const rdn = temp.rdnSerial();
      expect(rdn).toEqual(
        '3004751def2c78ae010000000100000061000000@' +
          `organizationName=${longName}` +
          '/organizationalUnitName=Адміністратор ІТС ЦЗО' +
          '/commonName=Центральний засвідчувальний орган' +
          '/serialNumber=UA-00015622-2012' +
          '/countryName=UA' +
          '/localityName=Київ'
      );
    });
  });

  describe('parse CZO root', () => {
    const data = fs.readFileSync(`${__dirname}/data/CZOROOT.cer`);

    it('should parse certificate', () => {
      const cert = jk.Certificate.from_asn1(data);
      expect(cert.format).toEqual('x509');
      expect(cert.signatureAlgorithm).toEqual('Dstu4145le');
      expect(cert.subject.serialNumber).toEqual('UA-00015622-2012');
      expect(cert.issuer).toEqual(cert.subject);
    });

    it('should verify validity of self-signed root', () => {
      const cert = jk.Certificate.from_asn1(data);
      expect(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash,
        })
      ).toEqual(true);
    });

    it('should verify validity of self-signed root (fail if messed with)', () => {
      const cert = jk.Certificate.from_asn1(data);
      cert.ob.tbsCertificate.issuer.value[0][0].value = Buffer.from('123');
      expect(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash,
        })
      ).toEqual(false);
    });

    it('should verify validity of self-signed root (fail if algo doesnt match)', () => {
      const cert = jk.Certificate.from_asn1(data);
      cert.signatureAlgorithm = 'ECDSA';
      expect(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash,
        })
      ).toEqual(false);
    });

    it('should verify validity of self-signed root (fail if expired)', () => {
      const cert = jk.Certificate.from_asn1(data);
      expect(
        cert.verifySelfSigned({
          time: 1700000000000,
          dstuHash: algo.hash,
        })
      ).toEqual(false);
    });

    it('should verify validity of self-signed root (fail if not active yet)', () => {
      const cert = jk.Certificate.from_asn1(data);
      expect(
        cert.verifySelfSigned({
          time: 1300000000000,
          dstuHash: algo.hash,
        })
      ).toEqual(false);
    });
  });

  describe('parse minjust ca (ecdsa)', () => {
    const data = fs.readFileSync(
      `${__dirname}/data/CA-Justice-ECDSA-261217.cer`
    );
    const pemData = fs.readFileSync(
      `${__dirname}/data/CA-Justice-ECDSA-261217.pem`
    );
    const cert = jk.Certificate.from_asn1(data);

    it('should parse certificate from binary', () => {
      expect(cert.format).toEqual('x509');
      expect(cert.curve).toEqual(null);
      expect(cert.curve_id).toEqual('secp256r1');

      expect(cert.valid.from).toEqual(1514314260000); // 2017-12-26 18:51:00
      expect(cert.valid.to).toEqual(1672080660000); // 2022-12-26 18:51:00
      expect(cert.serial).toEqual(
        57595595825646241314308569398321717626221363200
      );
      expect(cert.signatureAlgorithm).toEqual('ECDSA-SHA256');
      expect(cert.pubkeyAlgorithm).toEqual('ECDSA');
      expect(cert.extension.ipn).toEqual(null);

      expect(cert.subject.commonName).toEqual('CA of the Justice of Ukraine');
      expect(cert.subject.organizationName).toEqual('State enterprise "NAIS"');
      expect(cert.subject.organizationalUnitName).toEqual(
        'Certification Authority'
      );
      expect(cert.subject.countryName).toEqual('UA');
      expect(cert.subject.localityName).toEqual('Kyiv');
      expect(cert.subject.serialNumber).toEqual('UA-39787008-1217');

      expect(cert.issuer.commonName).toEqual('Central certification authority');
      expect(cert.issuer.organizationName).toEqual(
        'Ministry of Justice of Ukraine'
      );
      expect(cert.issuer.organizationalUnitName).toEqual(
        'Administrator ITS CCA'
      );
      expect(cert.issuer.countryName).toEqual('UA');
      expect(cert.issuer.localityName).toEqual('Kyiv');
      expect(cert.issuer.serialNumber).toEqual('UA-00015622-256');
    });

    it('should parse certificate from PEM', () => {
      const pemCert = jk.Certificate.from_pem(pemData);
      expect(pemCert).toEqual(cert);
    });

    it('should serialize back', () => {
      const der = cert.to_asn1();
      expect(der).toEqual(data);
    });

    it('should serialize to PEM', () => {
      const pem = cert.to_pem();
      expect(pem).toEqual(pemData.toString().trim());
    });

    it('should make issuer rdn', () => {
      const rdn = cert.rdnSerial();
      expect(rdn).toEqual(
        'a16ad03d02fa86c010000000100000090000000' +
          '@organizationName=Ministry of Justice of Ukraine' +
          '/organizationalUnitName=Administrator ITS CCA' +
          '/commonName=Central certification authority' +
          '/serialNumber=UA-00015622-256' +
          '/countryName=UA' +
          '/localityName=Kyiv' +
          '/organizationIdentifier=NTRUA-00015622'
      );
    });
  });

  describe('Generated Cert', () => {
    const curve = jk.std_curve('DSTU_PB_257');
    const priv = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/PRIV1.cer`)
    );
    const privEncE54B = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/KeyE54B.cer`)
    );
    const privEnc6929 = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/Key6929.cer`)
    );
    const privEnc40A0 = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/Key40A0.cer`)
    );

    it('should generate and self-sign a cert', () => {
      const name = {
        organizationName: 'Very Much CA',
        serialNumber: 'UA-99999999',
        localityName: 'Wakanda',
      };
      const serial = 14799991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: priv,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: '\x03\x02\x06\xC0',
        },
      });
      const data = cert.as_asn1();
      expect(fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`)).toEqual(
        data
      );
    });

    it('should generate and self-sign encryption cert 40A0', () => {
      const name = {
        organizationName: 'Very Much CA',
        serialNumber: 'UA-99999999',
        localityName: 'Wakanda',
      };
      const serial = 99991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEnc40A0,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: '\x03\x02\x03\x08',
        },
      });
      const data = cert.as_asn1();
      expect(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`)
      ).toEqual(data);
    });

    it('should generate and self-sign encryption cert 6929', () => {
      const name = {
        organizationName: 'Very Much CA',
        serialNumber: 'UA-99999991',
        localityName: 'Wakanda',
      };
      const serial = 99991111 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEnc6929,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: '\x03\x02\x03\x08',
        },
      });
      const data = cert.as_asn1();
      expect(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_6929.cer`)
      ).toEqual(data);
    });

    it('should generate and self-sign encryption cert E54B', () => {
      const name = {
        organizationName: 'Very Much CA',
        serialNumber: 'UA-99999999',
        localityName: 'Wakanda',
      };
      const serial = 14799991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEncE54B,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: '\x03\x02\x03\x08',
        },
      });
      const data = cert.as_asn1();
      expect(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_E54B.cer`)
      ).toEqual(data);
    });

    it('should check that self-signed cert is valid', () => {
      const data = fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`);
      const cert = jk.Certificate.from_asn1(data);

      expect(
        cert.verifySelfSigned({ time: 1550000000000, dstuHash: algo.hash })
      ).toEqual(true);
    });
  });
});
