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
package org.apache.iotdb.db.auth.authorizer;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.iotdb.db.auth.AuthException;
import org.apache.iotdb.db.auth.entity.Role;
import org.apache.iotdb.db.auth.entity.User;

/**
 * This interface provides all authorization-relative operations.
 * 这个接口提供了授权相关的操作
 */
public interface IAuthorizer {

    /**
     * Login for a user.
     * 用户登录接口
     *
     * @param username The username of the user.
     * @param password The password of the user.
     * @return True if such user exists and the given password is correct, else return false.
     * @throws AuthException if exception raised when searching for the user.
     */
    boolean login(String username, String password) throws AuthException;

    /**
     * Create a user with given username and password. New users will only be granted no privileges.
     * 通过给定的用户名+密码来创建一个用户，新用户被授权没有权限
     *
     * @param username is not null or empty
     * @param password is not null or empty
     * @throws AuthException if the given username or password is illegal or the user already exists. 用户名密码非法，或者用户已经存在，抛出异常
     */
    void createUser(String username, String password) throws AuthException;

    /**
     * Delete a user.
     * 删除用户
     *
     * @param username the username of the user.
     * @throws AuthException When attempting to delete the default administrator or the user does not
     *                       exists.
     */
    void deleteUser(String username) throws AuthException;

    /**
     * Grant a privilege on a seriesPath to a user.
     * 授权一个路径到某个用户
     *
     * @param username    The username of the user to which the privilege should be added.  需要被添加的用户名
     * @param path        The seriesPath on which the privilege takes effect. If the privilege is a
     *                    seriesPath-free privilege, this should be "root". 权限将产生作用的路径，
     * @param privilegeId An integer that represents a privilege. 代表权限的一个数字
     * @throws AuthException If the user does not exist or the privilege or the seriesPath is illegal
     *                       or the permission already exists. 用户不存在，权限非法，权限已经存在，则产生异常
     */
    void grantPrivilegeToUser(String username, String path, int privilegeId) throws AuthException;

    /**
     * Revoke a privilege on seriesPath from a user.
     * 在某个路径上移除一个权限
     *
     * @param username    The username of the user from which the privilege should be removed.
     * @param path        The seriesPath on which the privilege takes effect. If the privilege is a
     *                    seriesPath-free privilege, this should be "root".
     * @param privilegeId An integer that represents a privilege.
     * @throws AuthException If the user does not exist or the privilege or the seriesPath is illegal
     *                       or if the permission does not exist.
     */
    void revokePrivilegeFromUser(String username, String path, int privilegeId) throws AuthException;

    /**
     * Add a role.
     * 添加一个角色
     *
     * @param roleName the name of the role to be added.
     * @throws AuthException if exception raised when adding the role or the role already exists.
     */
    void createRole(String roleName) throws AuthException;

    /**
     * Delete a role.
     * 删除一个角色
     *
     * @param roleName the name of the role tobe deleted.
     * @throws AuthException if exception raised when deleting the role or the role does not exists.
     */
    void deleteRole(String roleName) throws AuthException;

    /**
     * Add a privilege on a seriesPath to a role.
     * 添加一个权限到某个路径或者角色中
     *
     * @param roleName    The name of the role to which the privilege is added.
     * @param path        The seriesPath on which the privilege takes effect. If the privilege is a
     *                    seriesPath-free privilege, this should be "root".
     * @param privilegeId An integer that represents a privilege.
     * @throws AuthException If the role does not exist or the privilege or the seriesPath is illegal
     *                       or the privilege already exists.
     */
    void grantPrivilegeToRole(String roleName, String path, int privilegeId) throws AuthException;

    /**
     * Remove a privilege on a seriesPath from a role.
     * 移除某个权限
     *
     * @param roleName    The name of the role from which the privilege is removed.
     * @param path        The seriesPath on which the privilege takes effect. If the privilege is a
     *                    seriesPath-free privilege, this should be "root".
     * @param privilegeId An integer that represents a privilege.
     * @throws AuthException If the role does not exist or the privilege or the seriesPath is illegal
     *                       or the privilege does not exists.
     */
    void revokePrivilegeFromRole(String roleName, String path, int privilegeId) throws AuthException;

    /**
     * Add a role to a user.
     * 将某个权限给某个用户
     *
     * @param roleName The name of the role to be added.
     * @param username The name of the user to which the role is added.
     * @throws AuthException If either the role or the user does not exist or the role already exists.
     */
    void grantRoleToUser(String roleName, String username) throws AuthException;

    /**
     * Revoke a role from a user.
     *
     * @param roleName The name of the role to be removed.
     * @param username The name of the user from which the role is removed.
     * @throws AuthException If either the role or the user does not exist or the role already exists.
     */
    void revokeRoleFromUser(String roleName, String username) throws AuthException;

    /**
     * Get the all the privileges of a user on a seriesPath.
     *
     * @param username The user whose privileges are to be queried.
     * @param path     The seriesPath on which the privileges take effect. If the privilege is a
     *                 seriesPath-free privilege, this should be "root".
     * @return A set of integers each present a privilege.
     * @throws AuthException if exception raised when finding the privileges.
     */
    Set<Integer> getPrivileges(String username, String path) throws AuthException;

    /**
     * Modify the password of a user.
     *
     * @param username    The user whose password is to be modified.
     * @param newPassword The new password.
     * @throws AuthException If the user does not exists or the new password is illegal.
     */
    void updateUserPassword(String username, String newPassword) throws AuthException;

    /**
     * Check if the user have the privilege on the seriesPath.
     *
     * @param username    The name of the user whose privileges are checked.
     * @param path        The seriesPath on which the privilege takes effect. If the privilege is a
     *                    seriesPath-free privilege, this should be "root".
     * @param privilegeId An integer that represents a privilege.
     * @return True if the user has such privilege, false if the user does not have such privilege.
     * @throws AuthException If the seriesPath or the privilege is illegal.
     */
    boolean checkUserPrivileges(String username, String path, int privilegeId) throws AuthException;

    /**
     * Reset the Authorizer to initiative status.
     */
    void reset() throws AuthException;

    /**
     * List existing users in the database.
     *
     * @return A list contains all usernames.
     */
    List<String> listAllUsers();

    /**
     * List existing roles in the database.
     *
     * @return A list contains all roleNames.
     */
    List<String> listAllRoles();

    /**
     * Find a role by its name.
     *
     * @param roleName the name of the role.
     * @return A role whose name is roleName or null if such role does not exist.
     */
    Role getRole(String roleName) throws AuthException;

    /**
     * Find a user by its name.
     *
     * @param username the name of the user.
     * @return A user whose name is username or null if such user does not exist.
     */
    User getUser(String username) throws AuthException;

    /**
     * Whether data water-mark is enabled for user 'userName'.
     *
     * @param userName
     * @return
     * @throws AuthException if the user does not exist
     */
    boolean isUserUseWaterMark(String userName) throws AuthException;

    /**
     * Enable or disable data water-mark for user 'userName'.
     *
     * @param userName
     * @param useWaterMark
     * @throws AuthException if the user does not exist.
     */
    void setUserUseWaterMark(String userName, boolean useWaterMark) throws AuthException;

    /**
     * get all user water mark status
     *
     * @return key->userName, value->useWaterMark or not
     */
    Map<String, Boolean> getAllUserWaterMarkStatus();

    /**
     * get all user
     *
     * @return key-> userName, value->user
     */
    Map<String, User> getAllUsers();

    /**
     * get all role
     *
     * @return key->userName, value->role
     */
    Map<String, Role> getAllRoles();

    /**
     * clear all old users info, replace the old users with the new one
     *
     * @param users new users info
     * @throws AuthException
     */
    void replaceAllUsers(Map<String, User> users) throws AuthException;

    /**
     * clear all old roles info, replace the old roles with the new one
     * 清楚所有的角色信息
     *
     * @param roles new roles info
     * @throws AuthException
     */
    void replaceAllRoles(Map<String, Role> roles) throws AuthException;
}
