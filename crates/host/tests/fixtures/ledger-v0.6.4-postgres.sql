--
-- PostgreSQL database dump
--

\restrict K2FvHYVG4CexvHM6l8ixWz8K8KmJTOJD8Ql27ltjmvj1LHcrHAeiHTvhNatqFS8

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: agent_sessions; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.agent_sessions VALUES ('bb780117-3599-4d4d-83e7-2710025f708d', 'Audit server_config.txt for misconfigurations', '0404644e51611c7ba0d9fe8cd6647b77e9ffb096b397966afb3058025717ae4f', 'running', 'ollama', 'mistral', '2026-08-11 15:32:14.056695+00', NULL, '9f8e7d6c5b4a39281716151413121110ffeeddccbbaa99887766554433221100', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a', 'did:key:z6Mkqum6aQwo2Cgk7VPhZiHzPNUjVxJpGQVu6RbrUsZmRs9s', NULL);


--
-- Data for Name: agent_events; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.agent_events VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000', '633c9f000b9bb60e342a2e55dc7838e931803f626c701c9a171024bb969aea70', '{"type": "genesis", "message": "ledger initialised"}', '2026-08-11 15:32:14.094512+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (2, 1, '633c9f000b9bb60e342a2e55dc7838e931803f626c701c9a171024bb969aea70', 'f809bbe36e0561c86615f5c6e7fb6783e70b76b8820161db6721693e6ea8d17c', '{"type": "prompt_input", "content": "Audit server_config.txt for misconfigurations"}', '2026-08-11 15:32:14.097176+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (3, 2, 'f809bbe36e0561c86615f5c6e7fb6783e70b76b8820161db6721693e6ea8d17c', '1e1eadaddeee2821de0f4e7a998c3185ec41c192db531f81fdd1497fe021a2ee', '{"type": "thought", "content": "Reading the config file to identify misconfigurations."}', '2026-08-11 15:32:14.098742+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (4, 3, '1e1eadaddeee2821de0f4e7a998c3185ec41c192db531f81fdd1497fe021a2ee', 'c0953a3a3497a3e78236dfbf299dffe6639122e4faa47f7a535b421408b72bb7', '{"name": "read_file", "type": "action", "params": {"path": "server_config.txt"}}', '2026-08-11 15:32:14.100323+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (5, 4, 'c0953a3a3497a3e78236dfbf299dffe6639122e4faa47f7a535b421408b72bb7', '17d7445b04d759f9bccbded8bbfbb1ff72dfcb27b7e0316f04b730fadb15f59b', '{"type": "observation", "content": "PermitRootLogin yes\nPort 22"}', '2026-08-11 15:32:14.102151+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (6, 5, '17d7445b04d759f9bccbded8bbfbb1ff72dfcb27b7e0316f04b730fadb15f59b', 'b4bec44294004123e7b7b881e0aba45c73dadfe91f4a9561fd21bd6d355d8dbe', '{"type": "thought", "content": "Guard denied: command outside the stated audit goal"}', '2026-08-11 15:32:14.104218+00', 'bb780117-3599-4d4d-83e7-2710025f708d');
INSERT INTO public.agent_events VALUES (7, 6, 'b4bec44294004123e7b7b881e0aba45c73dadfe91f4a9561fd21bd6d355d8dbe', '54da9527796abb563d2c0cad846127dd541df001b243a7c93b8cbc564057fc9e', '{"type": "thought", "content": "Sufficient evidence gathered; completing."}', '2026-08-11 15:32:14.105809+00', 'bb780117-3599-4d4d-83e7-2710025f708d');


--
-- Data for Name: agent_event_signatures; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.agent_event_signatures VALUES (1, '633c9f000b9bb60e342a2e55dc7838e931803f626c701c9a171024bb969aea70', '639d74f13a2dce4f72478aa7819f9f548ce2f5f0f8b206750935183f6c97150cc33cdd09631a16c48d04e1f39f834c525b3b3742ced186a274f7f31ce952ee0a', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (2, 'f809bbe36e0561c86615f5c6e7fb6783e70b76b8820161db6721693e6ea8d17c', '235311019812e32ccb6dbec300b8853278f85776eca315c9bfeba36a88b7b333792ef525d46329f4e5bf48837a3503d80b91e7b1aacffec4b0d7bfe425f8ff05', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (3, '1e1eadaddeee2821de0f4e7a998c3185ec41c192db531f81fdd1497fe021a2ee', 'c465e79a06637c8f65f62a6d0a1ffb55cad043ba3be34358646825dc29196f19e44934a7c1419b5dafdfab04833b266dbc0e179465768dadcb21d65c31a35408', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (4, 'c0953a3a3497a3e78236dfbf299dffe6639122e4faa47f7a535b421408b72bb7', '583e419415046ec16273244f58215576b7dd767a8fe2000b826ac663898bfc5c99a97920957fa1bc29ad07969b2832968433c2f1c4217960d6abfca0d4688f0a', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (5, '17d7445b04d759f9bccbded8bbfbb1ff72dfcb27b7e0316f04b730fadb15f59b', '0f1f10c05b94e56e906a5ef87c886c868f240147df5ce8a5a248cb2d394118aa37b496b227f74004a2593b57bde736e34cd5d48fddbb7f68f29d5bcc63b2b10d', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (6, 'b4bec44294004123e7b7b881e0aba45c73dadfe91f4a9561fd21bd6d355d8dbe', '5ab533123a5f76b464c48cec64495be3e5f48ce2301b44e57c37d40001d32f4ca3c23c2cf8bc5e753d478452c690cd095a83a0e25166b85112be3f5f89d0fe06', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');
INSERT INTO public.agent_event_signatures VALUES (7, '54da9527796abb563d2c0cad846127dd541df001b243a7c93b8cbc564057fc9e', '2adcf2f537b3ea0b5163d6a843f4f0f48595399814d8365eaae9c54f25e9ec4a7cf8dec02f350104294f508d4e8dc5d41c2e902de1e77c38fccc480aa595fe05', 'aa3a817e68cbf7c935d8a59927650a34ff06aeb2f3b903d7b40bcc72359b1a8a');


--
-- Name: agent_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.agent_events_id_seq', 7, true);


--
-- PostgreSQL database dump complete
--

\unrestrict K2FvHYVG4CexvHM6l8ixWz8K8KmJTOJD8Ql27ltjmvj1LHcrHAeiHTvhNatqFS8

