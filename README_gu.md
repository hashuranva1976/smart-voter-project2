# Smart Voter: પૂરો સુધારેલો પ્રોજેક્ટ

- `backend/`  : Flask સર્વર (Render પર). `smart_voter_db.sqlite` (નેતાઓનો ડેટા) અને `faces_faiss_idmap.index` સાથે.
- `frontend/` : Flutter એપ.

## શરૂ કરવા પહેલાં
1. `frontend/android/app/build.gradle.kts` માં `applicationId` બદલો (હાલ "in.yourorg.smartvoter").
2. Render માં: `SECRET_KEY`, `ADMIN_TOKEN` (32+ અક્ષર), `VOTING_DB_PATH=/data/voting.sqlite`, અને `/data` પર Persistent Disk.
3. `backend/voting_api.py` માં `deliver_otp()` માં SMS પ્રોવાઈડર જોડો.
4. ફ્રન્ટએન્ડમાં: `flutter pub get` → `flutter analyze` → `flutter build apk --release`.
5. ચૂંટણી/સભ્યો/ઉમેદવારો એડમિન API થી ઉમેરો (curl ઉદાહરણો અગાઉના README માં).

## `known_faces/` ફોલ્ડર
ફોટા અહીં મૂક્યા નથી (સર્વર ચલાવવા જરૂરી નથી). તમારા કમ્પ્યુટરમાં જ રાખો.
