# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import logging
from .agents import build_root_agent
from .config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set OpenAI API key if available
try:
    os.environ["OPENAI_API_KEY"] = settings.get_openai_api_key()
except ValueError as e:
    logger.warning(f"OpenAI API key configuration: {e}")

# Create the root agent using the new Agent-as-a-Tool architecture
root_agent = build_root_agent() 