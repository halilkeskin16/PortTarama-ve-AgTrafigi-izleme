# Generated by Django 4.2.1 on 2023-05-26 11:36

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0010_ipadresleri_islem_tarihi'),
    ]

    operations = [
        migrations.AddField(
            model_name='ports',
            name='servis_name',
            field=models.CharField(default=datetime.datetime(2023, 5, 26, 11, 36, 10, 36883, tzinfo=datetime.timezone.utc), max_length=20),
            preserve_default=False,
        ),
    ]
