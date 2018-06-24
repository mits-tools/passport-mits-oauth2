/* eslint-disable no-unused-expressions */
const chai = require('chai')
const expect = chai.expect

chai.use(require('chai-passport-strategy'))

const MitsStrategy = require('../lib')

describe('issuing authorization request', function () {
  describe('without parameters', function () {
    var strategy = new MitsStrategy({
      clientID: 'ABC123',
      clientSecret: 'secret'
    }, function () {})

    var url

    before(function (done) {
      chai.passport.use(strategy)
        .redirect(function (u) {
          url = u
          done()
        })
        .req(function (req) {
          req.session = {}
        })
        .authenticate({})
    })

    it('should be redirected to the right client id', function () {
      expect(url).to.equal('https://accounts.mits-tools.com/oauth/authorize?response_type=code&client_id=ABC123')
    })
  })

  describe('with scope parameter', function () {
    var strategy = new MitsStrategy({
      clientID: 'ABC123',
      clientSecret: 'secret'
    }, function () {})

    var url

    before(function (done) {
      chai.passport.use(strategy)
        .redirect(function (u) {
          url = u
          done()
        })
        .req(function (req) {
          req.session = {}
        })
        .authenticate({scope: 'profile'})
    })

    it('should be redirected with a scope', function () {
      expect(url).to.equal('https://accounts.mits-tools.com/oauth/authorize?response_type=code&scope=profile&client_id=ABC123')
    })
  })

  describe('with redirect_uri parameter', function () {
    var strategy = new MitsStrategy({
      clientID: 'ABC123',
      clientSecret: 'secret'
    }, function () {})

    var url

    before(function (done) {
      chai.passport.use(strategy)
        .redirect(function (u) {
          url = u
          done()
        })
        .req(function (req) {
          req.session = {}
        })
        .authenticate({callbackURL: 'https://www.example.com/home'})
    })

    it('should be redirected with a redirect uri', function () {
      expect(url).to.equal('https://accounts.mits-tools.com/oauth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.com%2Fhome&client_id=ABC123')
    })
  })
})

describe('client that initiates strategy given a different authorization url', function () {
  var strategy = new MitsStrategy({
    authorizationURL: 'https://test.mits-tools.com/oauth/authorize',
    clientID: 'ABC123',
    clientSecret: 'secret'
  }, function () {})

  var url

  before(function (done) {
    chai.passport.use(strategy)
      .redirect(function (u) {
        url = u
        done()
      })
      .req(function (req) {
        req.session = {}
      })
      .authenticate({})
  })

  it('should be redirected to the right authorization url', function () {
    expect(url).to.equal('https://test.mits-tools.com/oauth/authorize?response_type=code&client_id=ABC123')
  })
})

describe('processing response to authorization request', function () {
  describe('that was approved without redirect URI', function () {
    var strategy = new MitsStrategy({
      authorizationURL: 'https://example.mits-tools.com/oauth2/authorize',
      userProfileURL: 'https://example.mits-tools.com/userinfo',
      clientID: 'ABC123',
      clientSecret: 'secret'
    },
    function (accessToken, refreshToken, profile, done) { })

    strategy._oauth2.get = function (url, accessToken, callback) {
      if (url !== 'https://example.mits-tools.com/userinfo') { return callback(new Error('incorrect url argument')) }
      if (accessToken !== 'token') { return callback(new Error('incorrect token argument')) }

      var body = '{"realm":null,"username":"example@mits-tools.com","email":"example@mits-tools.com","emailVerified":true,"verificationToken":null,"id":1234,"displayName":"Example Exampleson","familyName":"Exampleson","givenName":"Example"}'
      callback(null, body, undefined)
    }

    var profile

    before(function (done) {
      strategy.userProfile('token', function (err, p) {
        if (err) { return done(err) }
        profile = p
        done()
      })
    })

    it('should parse profile', function () {
      expect(profile.provider).to.equal('mits')

      expect(profile.id).to.equal(1234)
      expect(profile.email).to.equal('example@mits-tools.com')
      expect(profile.emailVerified).to.be.true
    })

    it('should set raw property', function () {
      expect(profile._raw).to.be.a('string')
    })

    it('should set json property', function () {
      expect(profile._json).to.be.an('object')
    })
  })
})
