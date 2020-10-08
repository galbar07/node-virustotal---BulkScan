const nvt = require('node-virustotal');
fs = require('fs');
const converter = require('json-2-csv');
const lineReader = require('line-reader');
var someData =[]

const defaultTimedInstance = nvt.makeAPI();


lineReader.eachLine('scan.txt', (line, last) => { 
const theSameObject = defaultTimedInstance.ipLookup(line, function(err, res){
  if (err) {
    console.log('Well, crap.');
    console.log(err);
    return;
  }
  const obj = JSON.parse(res);
  someData.push({ "Ip" : line,
  "harmless":obj.data.attributes.last_analysis_stats.harmless,
  "malicious":obj.data.attributes.last_analysis_stats.malicious,
  "suspicious":obj.data.attributes.last_analysis_stats.suspicious,
    "country" : obj.data.attributes.country ,
    "owner":obj.data.attributes.as_owner});
 
  converter.json2csv(someData, (err, csv) => {
    if (err) {
        throw err;
    }
    // print CSV string
    console.log(csv);
    // write CSV to a file
    fs.writeFileSync('results.csv', csv); 
});
}); 

  return;
});