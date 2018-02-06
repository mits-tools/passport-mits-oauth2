'use strict'

const OAuth2Strategy = require('passport-oauth2')
const debug = require('debug')('passport-mits-oauth2')
const util = require('util')

function Strategy(options, verify) {
  options = options || {}

  options.authorizationURL =
    options.authorizationURL ||
    'https://accounts.mits-tools.com/oauth/authorize'
  options.tokenURL =
    options.tokenURL || 'https://accounts.mits-tools.com/oauth/token'
  OAuth2Strategy.call(this, options, verify)
  this.name = 'mits-accounts'
  this._userProfileURL =
    options.userProfileURL || 'https://accounts.mits-tools.com/userinfo'
}

util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function(accessToken, done) {
  const self = this
  this._oauth2.get(this._userProfileURL, accessToken, (err, body, res) => {
    if (err) {
      debug('fetch error: %o', err)
      return done(new Error('Failed to fetch user profile'))
    }
    try {
      json = JSON.parse(body)
    } catch (ex) {
      debug('parse error: %o', ex)
      return done(new Error('Failed to parse user profile'))
    }

    profile.provider = 'mits'
    profile.id = json.id
    profile._raw = body
    profile._json = json

    done(null, profile)
  })
}

module.exports = Strategy
