const app = require('./app');
const PORT = 3000;
 
app.listen(process.env.PORT || PORT, function(err){
    if (err) console.log("Error in server setup")
    console.log("Server listening on Port", PORT);
});
//app.listen(process.env.PORT || 3000, ()=>{
  console.log('started express server');
//});
