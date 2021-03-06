'use strict'

const OAuth2Strategy = require('passport-oauth2')
const debug = require('debug')('passport-mits-oauth2')
const util = require('util')

function Strategy (options, verify) {
  options = options || {}

  options.authorizationURL =
    options.authorizationURL ||
    'https://accounts.mits-tools.com/oauth/authorize'
  options.revokeURL =
    options.revokeURL || 'https://accounts.mits-tools.com/oauth/revoke'
  options.tokenURL =
    options.tokenURL || 'https://accounts.mits-tools.com/oauth/token'
  OAuth2Strategy.call(this, options, verify)
  this.name = options.name || 'mits-accounts'
  this._userProfileURL =
    options.userProfileURL || 'https://accounts.mits-tools.com/userinfo'
}

util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.revokeToken = function (accessToken, done) {
  this._oauth2.get(this.revokeUrl, accessToken, (err) => {
    if (err) {
      debug('fetch error: %o', err)
      return done(new Error('Failed to revoke access token'))
    } else {
      return done()
    }
  })
}

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, (err, body, res) => {
    if (err) {
      debug('fetch error: %o', err)
      return done(new Error('Failed to fetch user profile'))
    }
    const profile = {
      _raw: body,
      provider: 'mits'
    }
    try {
      const json = JSON.parse(body)
      profile._json = json
      profile.id = json.id
      profile.email = json.email
      profile.emailVerified = json.emailVerified
    } catch (ex) {
      debug('parse error: %o', ex)
      return done(new Error('Failed to parse user profile'))
    }

    done(null, profile)
  })
}

Strategy.prototype.authorizationParams = function (options) {
  debug('setting authorization params: %o', options)
  return options
}

OAuth2Strategy.prototype.tokenParams = function(options) {
  debug('setting token params: %o', options)
  return options;
};

module.exports = Strategy
