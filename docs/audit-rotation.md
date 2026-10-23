# Audit rotation และการกู้คืน

`AuditWriter::rotate(suffix)` แบ่ง log เป็น archive และ active log โดยไฟล์ใหม่
เริ่มด้วย `resume` record (`seq=0`, `hash_prev` ชี้ seal ของ archive) จึงเปิดโปรแกรม
ใหม่ก่อนมี action ถัดไปได้โดยไม่ลืมรอยต่อ ใช้ `verify_sequence` หรือ `aivm audit`
ตรวจ chain ข้ามไฟล์; จำนวน records รวม `seal` และ `resume` ด้วย

`verify_sequence` และ `aivm audit` ต้องมี genesis (record แรกของไฟล์แรกมี
`hash_prev` ว่าง) ถ้า archive ต้นสายหายจะคืน error ว่าประวัติไม่ครบ
ใช้ `AuditWriter::verify` / `aivm verify-audit` เมื่อต้องการตรวจเพียง snapshot
หรือ continuation ไฟล์เดียว ผลของคำสั่งนั้นไม่ยืนยันความครบถ้วนของประวัติก่อนหน้า

## ลำดับการเขียน

1. ตรวจ suffix และชื่อ archive ก่อนเขียน seal; ชื่อซ้ำรวม dangling symlink
   ถูกปฏิเสธโดยไม่เปลี่ยน active log
2. Append และ sync seal ใน active log
3. เขียน journal ที่มีชื่อ archive และ seal ลงไฟล์ 0600, sync แล้ว publish
   เป็น `audit.jsonl.rotation` แบบไม่เขียนทับ พร้อม sync directory
4. พยายามปลด append-only flag ของ active log หลัง journal ถูก sync แล้ว
   เพื่อให้ filesystem อนุญาต hard link/rename จากนั้นสร้าง hard link ไปยัง archive
   แบบ atomic และ sync directory หากสิทธิ์ไม่พอ การทำไฟล์จะคืน error โดยเก็บ journal ไว้
5. เขียน `resume` ลง staging file 0600 และ sync ก่อน rename ทับ active log
   แบบ atomic แล้ว sync directory ตอนนี้ active log และ archive แยก inode กัน
6. พยายามตั้ง append-only ให้ active log และ immutable ให้ archive ตามที่ filesystem
   และสิทธิ์รองรับ จากนั้นลบ journal และ sync directory

ผู้เรียกต้อง serialize writers ไปยัง path เดียวกันตลอดทั้ง open/append/rotate;
supervisor ใช้ VM lease อยู่แล้ว การสร้าง `AuditWriter` หลายตัวเพื่อเขียนพร้อมกัน
ไม่ได้รับการรองรับ Suffix ต้องไม่ว่างและมีเฉพาะ ASCII ตัวอักษร ตัวเลข `-_.`
CLI เรียง archive ตามชื่อ จึงควรใช้ suffix ที่เรียงตามเวลาหรือเลขลำดับแบบเติมศูนย์

## เมื่อโปรแกรมหยุดหรือคำสั่งล้มเหลว

- ก่อน publish journal: log เดิมยังอยู่ อาจมี seal เพิ่มแล้วแต่ยังไม่มี archive;
  เปิดต่อหรือ retry ได้ การคืน error หลังเริ่ม rotate จึงไม่รับประกันว่าไฟล์ไม่เปลี่ยน
- เมื่อ journal มีอยู่: `open`, `append` และ `rotate` จะกู้ transaction ก่อนเขียนต่อ
  โดยตรวจ seal, archive และ active log ก่อนสร้าง archive ที่ยังขาดหรือ swap ไฟล์ใหม่
  ถ้าหยุดขณะที่สองชื่อยังเป็น hard link กัน ระบบจะแยก active log ก่อน append
- หลัง swap แต่ก่อนลบ journal: ระบบจำ `resume` ที่ติดตั้งแล้วได้และจบ transaction
  โดยไม่สร้าง record ซ้ำ ถ้า `rotate` คืน error แต่ recovery ทำสำเร็จแล้ว การเรียก
  rotate ด้วย suffix เดิมจะถูกปฏิเสธเพราะ archive มีอยู่ ให้ตรวจ chain ก่อนเริ่มรอบใหม่
- Journal เสีย, log มี partial record, archive ไม่ตรง seal หรือ active log เปลี่ยน
  จากที่ journal ระบุ: หยุดแบบ fail-closed และเก็บหลักฐานเดิมไว้ ไม่ truncate หรือ reset chain

เมื่อพบไฟล์เสีย ให้หยุด writers และเก็บสำเนาทั้ง directory รวม journal และ staging
ก่อนตรวจสอบ อย่าลบ journal เพื่อให้ระบบเริ่มใหม่ หากเป็น I/O error เช่น filesystem
เต็ม ให้แก้สาเหตุแล้วเปิด runtime ใหม่เพื่อให้ recovery ทำงาน หากหลักฐานเสียจริง
ต้องให้ operator พิจารณากู้จากสำเนาที่เชื่อถือได้และบันทึกเหตุการณ์กู้คืน

`audit.jsonl.rotation-tmp` เป็น staging ของ journal ส่วน `audit.jsonl.rotation-next`
เป็น staging ของ active log ชื่อเหล่านี้ไม่ถูกนับเป็น archive และ staging ที่เขียน
ไม่ครบจะถูกสร้างใหม่เมื่อ retry/recovery ดำเนินต่อ

## หลักฐานทดสอบและขอบเขต

`cargo test -p aivm-audit` มี subprocess ที่ exit โดยไม่ unwind ระหว่าง rotate
9 จุด รวมก่อน/หลัง publish journal, หลังสร้าง archive และก่อน/หลัง swap
จากนั้นเปิดใหม่ append และตรวจทั้ง chain พร้อมเทียบ archive ว่าไม่เปลี่ยน
มีการทดสอบ I/O error ที่ staging, restart ก่อน action ใหม่, suffix ซ้ำ,
archive ขัดแย้ง, journal เสีย และหลายรอบ rotation ด้วย

การทดสอบนี้จำลอง process หยุดและ filesystem error ที่ระบุ ไม่ได้จำลองไฟดับหรือ
รับรอง storage ทุกชนิด การใช้ `sync_all` กับไฟล์และ directory อาศัย filesystem
ที่รองรับ hard link, atomic rename และการ sync ตามสัญญาของระบบปฏิบัติการ
FS flags เป็น best-effort และ hash chain ยังมี trust boundary ตาม
[architecture.md](architecture.md) โดยต้องมี checkpoint ภายนอกที่เชื่อถือได้
หากต้องการตรวจการแก้ chain ใหม่ทั้งชุดโดยผู้ดูแล host
