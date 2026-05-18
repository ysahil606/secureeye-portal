
import axios from 'axios';

const DEEPSEEK_API_KEY = 'sk-e43070ab39124e23a33952346406b0dc';
const API_URL = 'https://api.deepseek.com/v1/chat/completions';

async function testDeepSeek() {
    console.log('--- Testing DeepSeek API Connection ---');
    try {
        const response = await axios.post(
            API_URL,
            {
                model: 'deepseek-chat',
                messages: [
                    { role: 'system', content: 'You are a cybersecurity expert.' },
                    { role: 'user', content: 'Provide a 1-sentence summary of the CVE-2024-3400 vulnerability.' }
                ],
                max_tokens: 100
            },
            {
                headers: {
                    'Authorization': `Bearer ${DEEPSEEK_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('SUCCESS: API is working properly.');
        console.log('Response Content:', response.data.choices[0].message.content);
        process.exit(0);
    } catch (error) {
        console.error('FAILURE: API check failed.');
        if (error.response) {
            console.error(`Status: ${error.response.status}`);
            console.error('Data:', JSON.stringify(error.response.data, null, 2));
        } else {
            console.error('Error Message:', error.message);
        }
        process.exit(1);
    }
}

testDeepSeek();
