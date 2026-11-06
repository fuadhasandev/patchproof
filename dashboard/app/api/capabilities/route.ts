import { backend } from '@/lib/backend';
export const dynamic = 'force-dynamic';
export function GET(request: Request) { return backend(request, '/v1/capabilities'); }
