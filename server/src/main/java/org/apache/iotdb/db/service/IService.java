/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.iotdb.db.service;

import org.apache.iotdb.db.exception.ShutdownException;
import org.apache.iotdb.db.exception.StartupException;

public interface IService {

    /**
     * Start current service.
     * 开始当前的服务
     */
    void start() throws StartupException;

    /**
     * Stop current service. If current service uses thread or thread pool, current service should
     * guarantee to putBack thread or thread pool.
     * 停止当前的服务，假如当前服务使用线程或者线程池，当前服务应该保证putback线程和线程池
     */
    void stop();

    /**
     * 停止和等待
     *
     * @param milliseconds
     */
    default void waitAndStop(long milliseconds) {
        stop();
    }

    default void shutdown(long milliseconds) throws ShutdownException {
        waitAndStop(milliseconds);
    }

    /**
     * Get the name of the the service.
     * 获取服务的ID
     *
     * @return current service name
     */
    ServiceType getID();
}
