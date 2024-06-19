package io.curity.identityserver.plugin.data.access.migration;

import io.curity.identityserver.plugin.data.access.migration.config.MigrationDataAccessProviderConfiguration;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.datasource.CredentialDataAccessProviderFactory;
import se.curity.identityserver.sdk.datasource.CredentialVerifyingDataAccessProvider;
import se.curity.identityserver.sdk.service.ExceptionFactory;

public final class MigrationCredentialDataAccessProvider implements CredentialVerifyingDataAccessProvider, CredentialDataAccessProviderFactory
{
    private final MigrationDataAccessProviderConfiguration _configuration;
    private final ExceptionFactory _exceptionFactory;

    public MigrationCredentialDataAccessProvider(MigrationDataAccessProviderConfiguration configuration,
                                                 ExceptionFactory exceptionFactory)
    {
        _configuration = configuration;
        _exceptionFactory = exceptionFactory;
    }

    @Override
    public VerifyResult verify(SubjectAttributes subject, String password)
    {
        boolean isMigratedAndMatching = _configuration.getMigratedCredentialManager()
                .verifyPassword(subject.getSubject(), password);

        if (!isMigratedAndMatching)
        {
            boolean isInLegacy = _configuration.getLegacyCredentialManager()
                    .verifyPassword(subject.getSubject(), password);
            if (isInLegacy)
            {
                // TODO: Move to new DS
                return new VerifyResult.Accepted(AuthenticationAttributes.of(subject, ContextAttributes.empty()));
            }
            return new VerifyResult.Rejected("Not found in either DS");
        }
        return new VerifyResult.Accepted(AuthenticationAttributes.of(subject, ContextAttributes.empty()));
    }

    @Override
    public SetResult set(SubjectAttributes subject, String password)
    {
        throw _exceptionFactory.methodNotAllowed();
    }
}
