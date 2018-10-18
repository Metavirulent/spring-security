/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls;

import static org.assertj.core.api.Assertions.*;

import static org.mockito.Mockito.*;

import java.io.Serializable;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class AclPermissionEvaluatorTests {
	private AclService service;
	private ObjectIdentityRetrievalStrategy oidStrategy;
	private ObjectIdentityGenerator oidGenerator;
	private SidRetrievalStrategy sidStrategy;

	@Before
	public void setup() {
		service = mock(AclService.class);
		oidStrategy = mock(ObjectIdentityRetrievalStrategy.class);
		oidGenerator = mock(ObjectIdentityGenerator.class);
		sidStrategy = mock(SidRetrievalStrategy.class);
		ObjectIdentity oid = mock(ObjectIdentity.class);
		when(oidStrategy.getObjectIdentity(anyObject())).thenReturn(oid);
		when(oidGenerator.createObjectIdentity(any(Serializable.class), any(String.class))).thenReturn(oid);
		when(service.getObjectIdentityRetrievalStrategy()).thenReturn(oidStrategy);
		when(service.getSidRetrievalStrategy()).thenReturn(sidStrategy);
		when(service.getObjectIdentityGenerator()).thenReturn(oidGenerator);

		Acl acl = mock(Acl.class);

		when(service.readAclById(any(ObjectIdentity.class), anyListOf(Sid.class))).thenReturn(acl);
		when(acl.isGranted(anyListOf(Permission.class), anyListOf(Sid.class), eq(false))).thenReturn(true);
	}

	@Test
	public void hasPermissionReturnsTrueIfAclGrantsPermission() throws Exception {
		AclPermissionEvaluator pe = new AclPermissionEvaluator(service);
		assertThat(pe.hasPermission(mock(Authentication.class), new Object(), "READ")).isTrue();
	}

	@Test
	public void resolvePermissionNonEnglishLocale() {
		Locale systemLocale = Locale.getDefault();
		Locale.setDefault(new Locale("tr"));

		AclPermissionEvaluator pe = new AclPermissionEvaluator(service);
		assertThat(pe.hasPermission(mock(Authentication.class), new Object(), "write")).isTrue();

		Locale.setDefault(systemLocale);
	}
}
