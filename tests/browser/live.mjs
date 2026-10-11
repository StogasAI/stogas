// Shared by every JavaScript runtime. Sends an invalid API key through the
// environment's encrypted gateway, then checks refresh and close.
export async function checkLiveGateway(StogasTransport, environment) {
	const transport = await StogasTransport.create({ environment });
	try {
		const response = await transport.fetch(`${transport.baseURL}/chat/completions`, {
			method: 'POST',
			headers: {
				authorization: 'Bearer stogas-status-monitor-uncredentialed',
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				model: 'stogas-status-monitor',
				messages: [{ role: 'user', content: 'ping' }]
			})
		});
		const body = await response.json();
		if (response.status !== 401 || body.error?.type !== 'authentication_error')
			throw new Error(`The gateway did not reject the invalid key: ${response.status}`);
		await Promise.all([transport.refreshBundle(), transport.refreshBundle()]);
	} finally {
		await transport.close();
	}
	await transport.close();
	const refused = await transport.refreshBundle().then(
		() => false,
		(error) => error.message === 'Transport closed'
	);
	if (!refused) throw new Error('A closed transport accepted a refresh');
}
