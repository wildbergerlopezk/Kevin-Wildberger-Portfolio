// middleware/errorHandler.js
function errorHandler(err, req, res, next) {
  console.error(err.stack); 

  const status = err.status || 500; 
  const message = err.message || "Internal Server Error"; 

  res.status(status).json({ message, details: err.details || {} }); // JSON response with the error message
}

module.exports = errorHandler;
