const axios = require('axios');

async function fetchWigleData(bssid) {
  try {
    const response = await axios.get('https://api.wigle.net/api/v2/network/detail', {
      headers: {
        'Authorization': "Basic YOUR-WGILE-KEY" // Replace with your Wigle API key
      },
      params: {
        netid: bssid
      }
    });
    if (response.data && response.data.results && response.data.results.length > 0) {
      const { trilat: lat, trilong: lon } = response.data.results[0];
      console.log(`BSSID: ${bssid}, lat: ${lat}, lon: ${lon}`);
    } else {
      console.log(`No data found for BSSID: ${bssid}`);
    }
  } catch (err) {
    console.error(`Error fetching data for BSSID: ${bssid}`, err);
  }
}

const testBSSID = 'testBSSID'; // Replace with the BSSID you want to test
fetchWigleData(testBSSID);
