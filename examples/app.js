// Synthetic example for local analysis; not evidence of a real service.
fetch('/api/v1/profile');
axios.get('/api/v1/projects/123/export?format=json');
const graphqlEndpoint = '/graphql/query';
fetch('/api/v1/projects/' + projectId); // Only the literal prefix can be recovered.
fetch(`/api/v1/projects/${projectId}`); // Computed template intentionally skipped.
const thirdParty = 'https://outside.example.net/metrics'; // Out of scope.

