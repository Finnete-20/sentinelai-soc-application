const BASE_URL = "https://sentinelai-backend-w5bu.onrender.com";

export async function investigate(input) {
    try {
        const response = await fetch(
            `${BASE_URL}/investigate`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    input
                })
            }
        );

        if (!response.ok) {
            throw new Error(
                `Server returned ${response.status}`
            );
        }

        const data = await response.json();

        return {
            success: true,
            data
        };

    } catch (error) {

        return {
            success: false,
            error: error.message
        };
    }
}