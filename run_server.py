#!/usr/bin/env python
"""Quick server runner."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("artemis.web.app:app", host="0.0.0.0", port=8890)
