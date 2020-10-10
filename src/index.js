const electron = require('electron'); 
const path = require('path'); 
const fs = require('fs'); 
const nvt = require('node-virustotal');
const converter = require('json-2-csv');
const lineReader = require('line-reader');
const readline = require('readline');
const readLastLines = require('read-last-lines');

let lastLine = "";

let count = 0;

var someData =[]
const defaultTimedInstance = nvt.makeAPI();


// Importing dialog module using remote 
const dialog = electron.remote.dialog; 
  
var uploadFile = document.getElementById('upload'); 
  
// Defining a Global file path Variable to store  
// user-selected file 
global.filepath = undefined; 
  
uploadFile.addEventListener('click', () => { 
// If the platform is 'win32' or 'Linux' 
    if (process.platform !== 'darwin') { 
        // Resolves to a Promise<Object> 
        dialog.showOpenDialog({ 
            title: 'Select the File to be uploaded', 
            defaultPath: path.join(__dirname, '../assets/'), 
            buttonLabel: 'Upload', 
            // Restricting the user to only Text Files. 
            filters: [ 
                { 
                    name: 'Text Files', 
                    extensions: ['txt', 'docx'] 
                }, ], 
            // Specifying the File Selector Property 
            properties: ['openFile'] 
        }).then(file => { 
            // Stating whether dialog operation was 
            // cancelled or not. 
            console.log(file.canceled); 
            if (!file.canceled) { 
              // Updating the GLOBAL filepath variable  
              // to user-selected file. 
              global.filepath = file.filePaths[0].toString(); 
              console.log(global.filepath);
              document.getElementById('tag-id').innerHTML = '<h5 style="margin:10px">Scanning...</h4>'
              + '<div style="margin:20px; padding: 10px;"  class="spinner-border text-primary" role="status">'+
              '<span class="sr-only">Loading...</span>'+'</div>';
            
              //getting last Ip
              readLastLines.read(global.filepath, 1)
              .then((lines) => lastLine+=lines);
          

              lineReader.eachLine(global.filepath, (line, last) => { 

                const theSameObject = defaultTimedInstance.ipLookup(line, function(err, res){
                  if (err) {
                    console.log('Well, crap.');
                    console.log(err);
                    return;
                  }
                  const obj = JSON.parse(res);
                  let engines = "";
                  
                  if(obj.data.attributes.last_analysis_stats.malicious>0){
                    let scan = obj.data.attributes.last_analysis_results;
                    Object.entries(scan).forEach(
                      ([key, value]) => {
                        if(value.result === "malicious" || value.result === "malware"){
                        engines += key + "\n";
                       }
                       
                      }
                  );
                  }
                  someData.push({ "Ip" : line,
                  "harmless":obj.data.attributes.last_analysis_stats.harmless,
                  "malicious":obj.data.attributes.last_analysis_stats.malicious,
                  "suspicious":obj.data.attributes.last_analysis_stats.suspicious,
                    "country" : obj.data.attributes.country ,
                    "owner":obj.data.attributes.as_owner,
                  "Engine detection" : engines});
                 
                  console.log(lastLine);
                  if(line != lastLine){
                    count++;
                    console.log("Total scans is " + count);
                  }
                  else{
                    document.getElementById("tag-id").remove();
                    document.getElementById('after').innerHTML = '<h3 style="margin:10px">Done</h3>'
                  }

                  converter.json2csv(someData, (err, csv) => {
                    if (err) {
                        throw err;
                    }
                    // print CSV string
                    // write CSV to a file
                    fs.writeFileSync('results.csv', csv); 
                });
                }); 
                
                  return;
                });

            }   
        }).catch(err => { 
            console.log(err) 
        }); 
    } 

}); 