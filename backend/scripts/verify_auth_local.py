import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


async def main() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "SentinelAdmin2026!"},
        )
        print("login", login_resp.status_code, login_resp.text[:300])

        if login_resp.status_code != 200:
            return

        token = login_resp.json().get("access_token")
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        print("me", me_resp.status_code, me_resp.text[:300])

        change_resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "SentinelAdmin2026!",
                "new_password": "SentinelAdmin2026!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        print("change-password", change_resp.status_code, change_resp.text[:300])


if __name__ == "__main__":
    asyncio.run(main())
