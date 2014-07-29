/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.util;

import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.log.LogChute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a simple SLF4J system that will either latch onto
 * an existing category, or just do a simple rolling file log.
 *
 * @author Mandus Elfving
 */
public class SLF4JLogChute implements LogChute {

    private static final String RUNTIME_LOG_SLF4J_LOGGER = "runtime.log.logsystem.slf4j.logger";

    private Logger logger = null;

    /**
     * @see org.apache.velocity.runtime.log.LogChute#init(org.apache.velocity.runtime.RuntimeServices)
     */
    public void init(RuntimeServices rs) throws Exception {
        String name = (String) rs.getProperty(RUNTIME_LOG_SLF4J_LOGGER);
        if (name != null) {
            logger = LoggerFactory.getLogger(name);
            log(DEBUG_ID, "SLF4JLogChute using logger '" + logger.getName() + '\'');
        } else {
            logger = LoggerFactory.getLogger(this.getClass());
            log(DEBUG_ID, "SLF4JLogChute using logger '" + logger.getClass() + '\'');
        }
    }

    /**
     * @see org.apache.velocity.runtime.log.LogChute#log(int, java.lang.String)
     */
    public void log(int level, String message) {
        switch (level) {
            case LogChute.WARN_ID:
                logger.warn(message);
                break;
            case LogChute.INFO_ID:
                logger.info(message);
                break;
            case LogChute.TRACE_ID:
                logger.trace(message);
                break;
            case LogChute.ERROR_ID:
                logger.error(message);
                break;
            case LogChute.DEBUG_ID:
            default:
                logger.debug(message);
                break;
        }
    }

    /**
     * @see org.apache.velocity.runtime.log.LogChute#log(int, java.lang.String, java.lang.Throwable)
     */
    public void log(int level, String message, Throwable t) {
        switch (level) {
            case LogChute.WARN_ID:
                logger.warn(message, t);
                break;
            case LogChute.INFO_ID:
                logger.info(message, t);
                break;
            case LogChute.TRACE_ID:
                logger.trace(message, t);
                break;
            case LogChute.ERROR_ID:
                logger.error(message, t);
                break;
            case LogChute.DEBUG_ID:
            default:
                logger.debug(message, t);
                break;
        }
    }

    /**
     * @see org.apache.velocity.runtime.log.LogChute#isLevelEnabled(int)
     */
    public boolean isLevelEnabled(int level) {
        switch (level) {
            case LogChute.DEBUG_ID:
                return logger.isDebugEnabled();
            case LogChute.INFO_ID:
                return logger.isInfoEnabled();
            case LogChute.TRACE_ID:
                return logger.isTraceEnabled();
            case LogChute.WARN_ID:
                return logger.isWarnEnabled();
            case LogChute.ERROR_ID:
                return logger.isErrorEnabled();
            default:
                return true;
        }
    }
}