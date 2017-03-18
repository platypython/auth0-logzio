const Path = require('path');
const Request = require('sync-request');
const Webpack = require('webpack');
const _ = require('lodash');
const pkg = require('./package.json');
let WebpackOnBuildPlugin = require('on-build-webpack');
let fs = require('fs');

const LIST_MODULES_URL = 'https://webtask.it.auth0.com/api/run/wt-tehsis-gmail_com-1?key=eyJhbGciOiJIUzI1NiIsImtpZCI6IjIifQ.eyJqdGkiOiJmZGZiOWU2MjQ0YjQ0YWYyYjc2YzAwNGU1NjgwOGIxNCIsImlhdCI6MTQzMDMyNjc4MiwiY2EiOlsiZDQ3ZDNiMzRkMmI3NGEwZDljYzgwOTg3OGQ3MWQ4Y2QiXSwiZGQiOjAsInVybCI6Imh0dHA6Ly90ZWhzaXMuZ2l0aHViLmlvL3dlYnRhc2tpby1jYW5pcmVxdWlyZS90YXNrcy9saXN0X21vZHVsZXMuanMiLCJ0ZW4iOiIvXnd0LXRlaHNpcy1nbWFpbF9jb20tWzAtMV0kLyJ9.MJqAB9mgs57tQTWtRuZRj6NCbzXxZcXCASYGISk3Q6c';

const res = Request('GET', LIST_MODULES_URL);
const modules = JSON.parse(res.getBody()).modules;

module.exports = {
  entry: _.set({}, pkg.name, './index.js'),
  output: {
    path: Path.join(__dirname, 'build'),
    filename: 'bundle.js',
    publicPath: '/build/',
    library: true,
    libraryTarget: 'commonjs2',
  },
  module: {
    loaders: [
      {
        test: /\.jsx?$/,
        exclude: /(node_modules|bower_components)/,
        loader: 'babel', // 'babel-loader' is also a legal name to reference
        query: {
          presets: ['react', 'es2015']
        }
      },
      {
        test: /\.json?$/,
        loader: 'json'
      }
    ]
  },
  externals: _(modules).reduce(function (acc, module) {
    return _.set(acc, module.name, true);
  }, {
    // Not provisioned via verquire
    'auth0-api-jwt-rsa-validation': true,
    'auth0-authz-rules-api': true,
    'auth0-oauth2-express': true,
    'auth0-sandbox-ext': true,
    'detective': true,
    'sandboxjs': true,
    'webtask-tools': true
  }),
  plugins: [
    new Webpack.optimize.DedupePlugin(),
    new Webpack.NoErrorsPlugin()
  ],
  resolve: {
    modulesDirectories: ['node_modules'],
    root: __dirname,
    alias: {},
  },
  node: {
    console:    false,
    global:     false,
    process:    false,
    Buffer:     false,
    __filename: false,
    __dirname:  false
  }
};
