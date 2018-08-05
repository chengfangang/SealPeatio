'use strict'
const express = require('express')
const helmet = require('helmet')
const morgan = require('morgan')
const path = require('path')
const apiRouter = require("./server/apiRouter")
const port = 8181
const web = express()

web.listen(port)
web.use(helmet())
web.use(express.static(path.resolve(__dirname, './public')))
web.use(morgan('short'))
web.use('/rpc', apiRouter)
console.log(`Portal is running at ${port}`)